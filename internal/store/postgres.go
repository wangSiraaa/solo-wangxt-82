package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

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
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("store: 读取迁移目录失败: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		sqlBytes, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return err
		}
		if _, err := s.pool.Exec(ctx, string(sqlBytes)); err != nil {
			return fmt.Errorf("store: 执行迁移 %s 失败: %w", name, err)
		}
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
	reviewKind := v.ReviewKind
	if reviewKind == "" {
		reviewKind = "gate"
	}
	var refTime any
	if v.ReferenceTime != nil {
		refTime = v.ReferenceTime.UTC()
	}
	row := tx.QueryRow(ctx, `
		INSERT INTO verifications
		(artifact_id, decision, decision_reason, signature_valid, issuer_trusted,
		 policy_allowed, digest_match, policy_id, policy_version, policy_content_sha256,
		 trust_root_version, detail_json, review_kind, classification, reference_time,
		 revocation_feed_version)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
		RETURNING id`,
		p.Artifact.ID, v.Decision, v.DecisionReason, v.SignatureValid, v.IssuerTrusted,
		v.PolicyAllowed, v.DigestMatch, v.PolicyID, v.PolicyVersion, v.PolicyContentSHA256,
		v.TrustRootVersion, string(v.DetailJSON), reviewKind, v.Classification, refTime,
		v.RevocationFeedVersion)
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

func (s *PostgresStore) GetArtifactByID(ctx context.Context, id int64) (*Artifact, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, name, sha256, size_bytes, first_seen_at
		FROM artifacts WHERE id=$1`, id)
	return scanArtifact(row)
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

const verificationColumns = `
		id, artifact_id, decision, decision_reason, signature_valid, issuer_trusted,
		policy_allowed, digest_match, policy_id, policy_version, policy_content_sha256,
		trust_root_version, evaluated_at, detail_json,
		COALESCE(review_kind,'gate'), COALESCE(classification,''), reference_time,
		revocation_feed_version`

func (s *PostgresStore) ListVerifications(ctx context.Context, artifactID int64) ([]Verification, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+verificationColumns+` FROM verifications WHERE artifact_id=$1 ORDER BY id`, artifactID)
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
	row := s.pool.QueryRow(ctx,
		`SELECT `+verificationColumns+` FROM verifications WHERE id=$1`, id)
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
	var refTime *time.Time
	if err := row.Scan(&v.ID, &v.ArtifactID, &v.Decision, &v.DecisionReason,
		&v.SignatureValid, &v.IssuerTrusted, &v.PolicyAllowed, &v.DigestMatch,
		&v.PolicyID, &v.PolicyVersion, &v.PolicyContentSHA256, &v.TrustRootVersion,
		&v.EvaluatedAt, &detail, &v.ReviewKind, &v.Classification, &refTime,
		&v.RevocationFeedVersion); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	v.DetailJSON = []byte(detail)
	v.ReferenceTime = refTime
	return &v, nil
}

// --- 撤销 / 可信时间证据 / 依赖链（0002） ---

func (s *PostgresStore) UpsertRevocationEvent(ctx context.Context, rec RevocationEventRecord) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO revocation_events
		(key_id, compromised_at, revoked_at, reason, feed_version, recorded_at)
		VALUES ($1,$2,$3,$4,$5,COALESCE($6, now()))
		ON CONFLICT (key_id) DO UPDATE SET
			compromised_at = EXCLUDED.compromised_at,
			revoked_at = EXCLUDED.revoked_at,
			reason = EXCLUDED.reason,
			feed_version = EXCLUDED.feed_version,
			recorded_at = EXCLUDED.recorded_at`,
		rec.KeyID, rec.CompromisedAt.UTC(), rec.RevokedAt.UTC(), rec.Reason,
		rec.FeedVersion, nilTime(rec.RecordedAt))
	return err
}

func nilTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC()
}

func (s *PostgresStore) ListRevocationEvents(ctx context.Context) ([]RevocationEventRecord, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT key_id, compromised_at, revoked_at, reason, feed_version, recorded_at
		FROM revocation_events ORDER BY key_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RevocationEventRecord
	for rows.Next() {
		var r RevocationEventRecord
		if err := rows.Scan(&r.KeyID, &r.CompromisedAt, &r.RevokedAt, &r.Reason,
			&r.FeedVersion, &r.RecordedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *PostgresStore) IngestTimeEvidence(ctx context.Context, p IngestTimeEvidenceParams) (int64, error) {
	var probe struct {
		Timestamp string `json:"timestamp"`
		TsaKeyID  string `json:"tsaKeyId"`
	}
	if err := jsonUnmarshal(p.Evidence, &probe); err != nil {
		return 0, fmt.Errorf("store: 时间证据 JSON 非法: %w", err)
	}
	ts, err := time.Parse(time.RFC3339, probe.Timestamp)
	if err != nil {
		return 0, fmt.Errorf("store: 时间证据时间戳非法: %w", err)
	}
	row := s.pool.QueryRow(ctx, `
		INSERT INTO trusted_time_evidence
		(envelope_sha256, tsa_key_id, trusted_timestamp, evidence_json)
		VALUES ($1,$2,$3,$4)
		ON CONFLICT (envelope_sha256, tsa_key_id, trusted_timestamp)
		DO UPDATE SET evidence_json = EXCLUDED.evidence_json
		RETURNING id`, p.EnvelopeSHA256, probe.TsaKeyID, ts.UTC(), string(p.Evidence))
	var id int64
	if err := row.Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

func (s *PostgresStore) ListTimeEvidence(ctx context.Context, envelopeSHA256 string) ([]TrustedTimeEvidenceRecord, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, envelope_sha256, tsa_key_id, trusted_timestamp, evidence_json, received_at
		FROM trusted_time_evidence WHERE envelope_sha256=$1
		ORDER BY trusted_timestamp`, envelopeSHA256)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TrustedTimeEvidenceRecord
	for rows.Next() {
		var r TrustedTimeEvidenceRecord
		var ev string
		if err := rows.Scan(&r.ID, &r.EnvelopeSHA256, &r.TSAKeyID,
			&r.TrustedTimestamp, &ev, &r.ReceivedAt); err != nil {
			return nil, err
		}
		r.EvidenceJSON = []byte(ev)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *PostgresStore) AddDependencyEdges(ctx context.Context, edges []DependencyEdge) error {
	for _, e := range edges {
		if _, err := s.pool.Exec(ctx, `
			INSERT INTO artifact_dependencies
			(artifact_id, attestation_id, dep_name, dep_sha256)
			VALUES ($1,$2,$3,$4)
			ON CONFLICT DO NOTHING`,
			e.ArtifactID, e.AttestationID, e.DepName, e.DepSHA256); err != nil {
			return fmt.Errorf("store: 保存依赖边失败: %w", err)
		}
	}
	return nil
}

func (s *PostgresStore) ListDependencyEdges(ctx context.Context, artifactID int64) ([]DependencyEdge, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, artifact_id, attestation_id, dep_name, dep_sha256
		FROM artifact_dependencies WHERE artifact_id=$1
		ORDER BY dep_name, dep_sha256, id`, artifactID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DependencyEdge
	for rows.Next() {
		var e DependencyEdge
		if err := rows.Scan(&e.ID, &e.ArtifactID, &e.AttestationID, &e.DepName, &e.DepSHA256); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *PostgresStore) FindArtifactByName(ctx context.Context, name string) ([]Artifact, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, sha256, size_bytes, first_seen_at
		FROM artifacts WHERE name=$1 ORDER BY id`, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Artifact
	for rows.Next() {
		a, err := scanArtifact(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

func (s *PostgresStore) ListDependentEdges(ctx context.Context, depName, depSHA string) ([]DependencyEdge, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, artifact_id, attestation_id, dep_name, dep_sha256
		FROM artifact_dependencies WHERE dep_name=$1 AND dep_sha256=$2
		ORDER BY id`, depName, depSHA)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DependencyEdge
	for rows.Next() {
		var e DependencyEdge
		if err := rows.Scan(&e.ID, &e.ArtifactID, &e.AttestationID, &e.DepName, &e.DepSHA256); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ExecTruncate 仅供集成测试清空表使用。
func (s *PostgresStore) ExecTruncate(ctx context.Context, table string) (string, error) {
	if !identifierSafe(table) {
		return "", fmt.Errorf("store: 非法表名 %q", table)
	}
	tag, err := s.pool.Exec(ctx, "TRUNCATE "+table+" RESTART IDENTITY CASCADE")
	return tag.String(), err
}

func identifierSafe(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_') {
			return false
		}
	}
	return true
}
