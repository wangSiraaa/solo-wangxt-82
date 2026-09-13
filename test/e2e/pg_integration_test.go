//go:build pg_integration

// 仅在设置 SCBVERIFY_PG_DSN 时运行的 PostgreSQL 集成测试。
// 运行：
//
//	SCBVERIFY_PG_DSN='postgres://postgres@127.0.0.1:5433/scbverify2?sslmode=disable' \
//	go test -tags pg_integration ./test/e2e -run TestPostgresRevocationReview -v
package e2e

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"scbverify/internal/policy"
	"scbverify/internal/review"
	"scbverify/internal/store"
	"scbverify/internal/timestampevidence"
	"scbverify/internal/verifier"
)

func TestPostgresRevocationReview(t *testing.T) {
	dsn := os.Getenv("SCBVERIFY_PG_DSN")
	if dsn == "" {
		t.Skip("未设置 SCBVERIFY_PG_DSN")
	}
	ctx := context.Background()
	pg, err := store.NewPostgresStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()

	f := loadRevocationFixture(t)
	// 用 PG 存储替换内存存储。
	f.h.st = pg

	// 清空相关表（集成库专用，可重复运行）。
	for _, tbl := range []string{
		"verification_attestations", "verifications", "artifact_dependencies",
		"trusted_time_evidence", "attestations", "artifacts", "policies",
	} {
		if _, err := pg.ExecTruncate(ctx, tbl); err != nil {
			t.Fatal(err)
		}
	}

	f.seedRevocationStore(t, map[string]bool{"root-insufficient-1.0.tar.gz": true})

	rootOrphan := "root-orphan-1.0.tar.gz"
	rootOrphanSHA := sha256Hex(mustReadFile(t,
		filepath.Join(f.h.demoRoot, "revocation", "artifacts", rootOrphan)))

	eng, err := policy.EmbeddedEngine()
	if err != nil {
		t.Fatal(err)
	}
	svc := review.NewService(pg, f.h.root, eng, f.feed, fixedClock)

	// seedRevocationStore 已对 root-orphan 做过一次 gate（撤销 => deny）。
	a0, err := pg.GetArtifact(ctx, rootOrphan, rootOrphanSHA)
	if err != nil {
		t.Fatal(err)
	}
	gateList, err := pg.ListVerifications(ctx, a0.ID)
	if err != nil {
		t.Fatal(err)
	}
	hasGate := false
	for _, v := range gateList {
		if v.ReviewKind == "gate" && v.Decision == verifier.DecisionDeny {
			hasGate = true
		}
	}
	if !hasGate {
		t.Fatal("seed 阶段应已保留 gate=deny 记录")
	}

	// 历史复核两次：新增 review 记录且不覆盖 gate/信封。
	envJSON := mustReadFile(t, filepath.Join(f.h.demoRoot,
		"revocation", "attestations", "att-"+rootOrphan+".json"))
	r1, err := svc.Review(ctx, rootOrphan, rootOrphanSHA)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := svc.Review(ctx, rootOrphan, rootOrphanSHA)
	if err != nil {
		t.Fatal(err)
	}
	if classOf(r1, rootOrphan) != "affected" || classOf(r2, rootOrphan) != "affected" {
		t.Fatalf("root-orphan 两次复核都应 affected: %s / %s",
			classOf(r1, rootOrphan), classOf(r2, rootOrphan))
	}
	a, err := pg.GetArtifact(ctx, rootOrphan, rootOrphanSHA)
	if err != nil {
		t.Fatal(err)
	}
	vs, err := pg.ListVerifications(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	var gates, reviews int
	var feedVer int
	for _, v := range vs {
		if v.ReviewKind == "gate" {
			gates++
		}
		if v.ReviewKind == "review" && v.Classification == "affected" {
			reviews++
			feedVer = v.RevocationFeedVersion
		}
	}
	if gates == 0 {
		t.Fatal("gate 记录必须保留")
	}
	if reviews != 2 {
		t.Fatalf("应新增 2 条 affected review，实际 %d", reviews)
	}
	if feedVer != 3 {
		t.Fatalf("复核记录必须带撤销清单版本 3，实际 %d", feedVer)
	}

	// 原始信封与 TSA 证据仍可取回且未被复核覆盖。
	recs, err := pg.ListAttestations(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("原始信封应保持 1 份，实际 %d", len(recs))
	}
	ttes, err := pg.ListTimeEvidence(ctx, canonicalEnvSHA(envJSON))
	if err != nil {
		t.Fatal(err)
	}
	if len(ttes) != 1 {
		t.Fatalf("应有 1 条 TSA 时间证据，实际 %d", len(ttes))
	}
	var ev timestampevidence.TrustedTimeEvidence
	if err := json.Unmarshal(ttes[0].EvidenceJSON, &ev); err != nil {
		t.Fatal(err)
	}
	if ev.EnvelopeSHA256 != canonicalEnvSHA(envJSON) {
		t.Fatal("时间证据必须绑定到原信封摘要")
	}

	// 依赖边与反查。
	edges, err := pg.ListDependentEdges(ctx, rootOrphan, rootOrphanSHA)
	if err != nil {
		t.Fatal(err)
	}
	if len(edges) < 1 {
		t.Fatal("root-orphan 应被下游固定引用")
	}
}
