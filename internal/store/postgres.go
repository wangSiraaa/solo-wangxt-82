package store

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/0001_init.sql
var migrationSQL string

// PostgresStore 通过 pgx 连接池实现 Store。
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore 建立连接池并执行幂等迁移。
func NewPostgresStore(ctx context.Context, dsn string) (*PostgresStore, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("store: 解析 DSN 失败: %w", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("store: 创建连接池失败: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: 连接 PostgreSQL 失败: %w", err)
	}
	s := &PostgresStore{pool: pool}
	if err := s.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return s, nil
}

func (s *PostgresStore) migrate(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx, migrationSQL); err != nil {
		return fmt.Errorf("store: 执行迁移失败: %w", err)
	}
	return nil
}

func (s *PostgresStore) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

func (s *PostgresStore) Close() error {
	s.pool.Close()
	return nil
}

func (s *PostgresStore) EnsureArtifact(ctx context.Context, a Artifact) (int64, error) {
	// upsert 保证重复核验幂等；不覆盖 first_seen_at。
	row := s.pool.QueryRow(ctx, `
		INSERT INTO artifacts (name, sha256, size_bytes)
		VALUES ($1, $2, $3)
		ON CONFLICT (name, sha256) DO UPDATE SET name = EXCLUDED.name
		RETURNING id`, a.Name, a.SHA256, a.SizeBytes)
	var id int64
	if err := row.Scan(&id); err != nil {
		return 0, fmt.Errorf("store: 登记产物失败: %w", err)
	}
	return id, nil
}

func (s *PostgresStore) AddAttestation(ctx context.Context, rec AttestationRecord) (int64, error) {
	row := s.pool.QueryRow(ctx, `
		INSERT INTO attestations (artifact_id, envelope_json, envelope_keyid, accepted_key_id, source_ref)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, received_at`,
		rec.ArtifactID, string(rec.EnvelopeJSON), rec.EnvelopeKeyID, rec.AcceptedKeyID, rec.SourceRef)
	var id int64
	var received time.Time
	if err := row.Scan(&id, &received); err != nil {
		return 0, fmt.Errorf("store: 保存证据失败: %w", err)
	}
	return id, nil
}

func (s *PostgresStore) RegisterPolicy(ctx context.Context, p PolicyVersion) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO policies (policy_id, policy_version, content_sha256)
		VALUES ($1,$2,$3)
		ON CONFLICT (policy_id, policy_version) DO NOTHING`,
		p.PolicyID, p.PolicyVersion, p.ContentSHA256)
	return err
}

func (s *PostgresStore) SaveVerification(ctx context.Context, p SaveVerificationParams) (int64, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("store: 开启事务失败: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	v := p.Verification
	row := tx.QueryRow(ctx, `
		INSERT INTO verifications
		(artifact_id, decision, decision_reason, signature_valid, issuer_trusted,
		 policy_allowed, digest_match, policy_id, policy_version, policy_content_sha256,
		 trust_root_version, detail_json)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		RETURNING id`,
		p.Artifact.ID, v.Decision, v.DecisionReason, v.SignatureValid, v.IssuerTrusted,
		v.PolicyAllowed, v.DigestMatch, v.PolicyID, v.PolicyVersion, v.PolicyContentSHA256,
		v.TrustRootVersion, string(v.DetailJSON))
	var vid int64
	if err := row.Scan(&vid); err != nil {
		return 0, fmt.Errorf("store: 写入判定失败: %w", err)
	}

	for _, av := range p.AttestationVerdicts {
		if _, err := tx.Exec(ctx, `
			INSERT INTO verification_attestations
			(verification_id, attestation_id, signature_valid, issuer_trusted,
			 policy_allowed, digest_match, conflict_with)
			VALUES ($1,$2,$3,$4,$5,$6,COALESCE($7, ARRAY[]::BIGINT[]))`,
			vid, av.AttestationID, av.SignatureValid, av.IssuerTrusted,
			av.PolicyAllowed, av.DigestMatch, av.ConflictWith); err != nil {
			return 0, fmt.Errorf("store: 写入逐项证明结论失败: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("store: 提交判定事务失败: %w", err)
	}
	return vid, nil
}

func (s *PostgresStore) GetArtifact(ctx context.Context, name, sha256 string) (*Artifact, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, name, sha256, size_bytes, first_seen_at
		FROM artifacts WHERE name=$1 AND sha256=$2`, name, sha256)
	a, err := scanArtifact(row)
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (s *PostgresStore) ListAttestations(ctx context.Context, artifactID int64) ([]AttestationRecord, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, artifact_id, envelope_json, envelope_keyid, accepted_key_id, received_at, source_ref
		FROM attestations WHERE artifact_id=$1 ORDER BY id`, artifactID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AttestationRecord
	for rows.Next() {
		var rec AttestationRecord
		var env string
		if err := rows.Scan(&rec.ID, &rec.ArtifactID, &env, &rec.EnvelopeKeyID,
			&rec.AcceptedKeyID, &rec.ReceivedAt, &rec.SourceRef); err != nil {
			return nil, err
		}
		rec.EnvelopeJSON = []byte(env)
		out = append(out, rec)
	}
	return out, rows.Err()
}

func (s *PostgresStore) ListVerifications(ctx context.Context, artifactID int64) ([]Verification, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, artifact_id, decision, decision_reason, signature_valid, issuer_trusted,
		       policy_allowed, digest_match, policy_id, policy_version, policy_content_sha256,
		       trust_root_version, evaluated_at, detail_json
		FROM verifications WHERE artifact_id=$1 ORDER BY id`, artifactID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Verification
	for rows.Next() {
		v, err := scanVerification(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *v)
	}
	return out, rows.Err()
}

func (s *PostgresStore) GetVerification(ctx context.Context, id int64) (*Verification, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, artifact_id, decision, decision_reason, signature_valid, issuer_trusted,
		       policy_allowed, digest_match, policy_id, policy_version, policy_content_sha256,
		       trust_root_version, evaluated_at, detail_json
		FROM verifications WHERE id=$1`, id)
	return scanVerification(row)
}

// rowScanner 兼容单行与多行结果。
type rowScanner interface {
	Scan(dest ...any) error
}

func scanArtifact(row rowScanner) (*Artifact, error) {
	var a Artifact
	if err := row.Scan(&a.ID, &a.Name, &a.SHA256, &a.SizeBytes, &a.FirstSeen); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &a, nil
}

func scanVerification(row rowScanner) (*Verification, error) {
	var v Verification
	var detail string
	if err := row.Scan(&v.ID, &v.ArtifactID, &v.Decision, &v.DecisionReason,
		&v.SignatureValid, &v.IssuerTrusted, &v.PolicyAllowed, &v.DigestMatch,
		&v.PolicyID, &v.PolicyVersion, &v.PolicyContentSHA256, &v.TrustRootVersion,
		&v.EvaluatedAt, &detail); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	v.DetailJSON = []byte(detail)
	return &v, nil
}
