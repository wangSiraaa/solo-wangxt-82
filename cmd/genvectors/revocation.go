package main

// 密钥撤销/历史复核确定性场景。
//
// 时间线（全部 UTC，便于可重复）：
//
//	2026-03-01  root-good 由被泄露的主机构建密钥签名，TSA 在泄露前盖时间戳
//	            => 撤销后复核：unaffected
//	2026-03-02  root-orphan 由同一被泄露密钥签名，TSA 在撤销后补盖时间戳
//	            => affected（撤销后补盖不能洗白）
//	2026-03-03  root-insufficient 由同一被泄露密钥签名，没有任何可信时间证据
//	            => insufficient（自报 metadata 时间不算可信历史证明）
//	2026-03-05  密钥泄露发生
//	2026-04-01  密钥正式撤销
//	2026-02-26  downstream-propagated 由被泄露密钥在泄露前签名/盖戳，但固定
//	            引用 root-orphan（affected）=> 仅因依赖传播而 affected
//	2026-03-02  downstream-once 引用 root-good（固定 sha256）
//	2026-03-03  downstream-twice-a 引用 downstream-once
//	2026-03-04  downstream-twice-b 引用 downstream-twice-a（多级传播，仍 unaffected）
//	2026-04-10  downstream-of-affected 泄露后签名且引用 root-orphan（affected）
//	2026-03-15  independent 不引用任何被泄露产物，用未泄露的第二构建者密钥
//
// 实时下载闸门：所有用被撤销密钥签名的证据一律 deny（不接受时间证据放行）。

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"time"

	"scbverify/internal/attestation"
	"scbverify/internal/cryptokit"
	"scbverify/internal/timestampevidence"
)

const (
	trustedBuilderSecondary = "https://build.example.com/builder/secondary"
	revocationScenarioName  = "revocation"
)

var (
	revCompromised = time.Date(2026, 3, 5, 0, 0, 0, 0, time.UTC)
	revRevoked     = time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
)

type revocationArtifact struct {
	name      string
	body      []byte
	signer    demoKey
	builderID string
	signedAt  time.Time // 仅用于 provenance 自报时间（不可信）
	deps      []revocationDependency
	tsaAt     *time.Time // 可信时间证据时间；nil 表示无 TSA 证据
}

type revocationDependency struct {
	name string
	sha  string
}

func rfc3339(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func mustMkdir(p string) { must(os.MkdirAll(p, 0o755)) }

func generateRevocationScenario(outDir string, compromised, secondary, tsa demoKey) map[string]any {
	mustMkdir(outDir)
	artDir := filepath.Join(outDir, "artifacts")
	attDir := filepath.Join(outDir, "attestations")
	tsDir := filepath.Join(outDir, "timestamps")
	mustMkdir(artDir)
	mustMkdir(attDir)
	mustMkdir(tsDir)

	// 两遍构造：先确定全部产物体与摘要，再回填链式依赖中的固定上游摘要。
	type pending struct {
		name, seed, builderID string
		signer                demoKey
		signedAt              time.Time
		deps                  []revocationDependency // 名字先填，sha 第二遍补
		tsaAt                 *time.Time
	}
	pendingList := []pending{
		{name: "root-good-1.0.tar.gz", seed: "root-good", builderID: trustedBuilder,
			signer: compromised, signedAt: time.Date(2026, 2, 28, 10, 0, 0, 0, time.UTC),
			tsaAt: ptrTime(time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC))},
		{name: "root-orphan-1.0.tar.gz", seed: "root-orphan", builderID: trustedBuilder,
			signer: compromised, signedAt: time.Date(2026, 3, 2, 10, 0, 0, 0, time.UTC),
			tsaAt: ptrTime(revRevoked.Add(24 * time.Hour))},
		{name: "root-insufficient-1.0.tar.gz", seed: "root-insufficient", builderID: trustedBuilder,
			// 自报时间在泄露前，但没有任何 TSA 证据：不能当作可信历史证明。
			signer: compromised, signedAt: time.Date(2026, 2, 20, 10, 0, 0, 0, time.UTC)},
		{name: "downstream-once-1.0.tar.gz", seed: "down-once", builderID: trustedBuilder,
			signer: compromised, signedAt: time.Date(2026, 3, 2, 9, 0, 0, 0, time.UTC),
			deps:  []revocationDependency{{name: "root-good-1.0.tar.gz"}},
			tsaAt: ptrTime(time.Date(2026, 3, 2, 12, 0, 0, 0, time.UTC))},
		{name: "downstream-twice-a-1.0.tar.gz", seed: "down-twice-a", builderID: trustedBuilder,
			signer: compromised, signedAt: time.Date(2026, 3, 3, 9, 0, 0, 0, time.UTC),
			deps:  []revocationDependency{{name: "downstream-once-1.0.tar.gz"}},
			tsaAt: ptrTime(time.Date(2026, 3, 3, 12, 0, 0, 0, time.UTC))},
		{name: "downstream-twice-b-1.0.tar.gz", seed: "down-twice-b", builderID: trustedBuilder,
			signer: compromised, signedAt: time.Date(2026, 3, 4, 9, 0, 0, 0, time.UTC),
			deps:  []revocationDependency{{name: "downstream-twice-a-1.0.tar.gz"}},
			tsaAt: ptrTime(time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC))},
		{name: "downstream-propagated-1.0.tar.gz", seed: "down-propagated", builderID: trustedBuilder,
			signer: compromised, signedAt: time.Date(2026, 2, 26, 9, 0, 0, 0, time.UTC),
			deps:  []revocationDependency{{name: "root-orphan-1.0.tar.gz"}},
			tsaAt: ptrTime(time.Date(2026, 2, 26, 12, 0, 0, 0, time.UTC))},
		{name: "downstream-of-affected-1.0.tar.gz", seed: "down-of-affected", builderID: trustedBuilder,
			signer: compromised, signedAt: time.Date(2026, 4, 10, 9, 0, 0, 0, time.UTC),
			deps:  []revocationDependency{{name: "root-orphan-1.0.tar.gz"}},
			tsaAt: ptrTime(time.Date(2026, 4, 10, 12, 0, 0, 0, time.UTC))},
		{name: "independent-1.0.tar.gz", seed: "independent", builderID: trustedBuilderSecondary,
			signer: secondary, signedAt: time.Date(2026, 3, 15, 9, 0, 0, 0, time.UTC),
			tsaAt: ptrTime(time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC))},
	}

	// 第一遍：全部产物体（体内容只依赖 name+seed），算出真实摘要。
	artSHAByName := map[string]string{}
	for _, p := range pendingList {
		body := []byte("# revocation scenario artifact: " + p.name + "\nseed:" + p.seed + "\n")
		sum := sha256.Sum256(body)
		artSHAByName[p.name] = hex.EncodeToString(sum[:])
	}
	// 第二遍：回填依赖固定摘要并构造 revocationArtifact。
	arts := make([]revocationArtifact, 0, len(pendingList))
	for _, p := range pendingList {
		deps := make([]revocationDependency, 0, len(p.deps))
		for _, d := range p.deps {
			deps = append(deps, revocationDependency{name: d.name, sha: artSHAByName[d.name]})
		}
		body := []byte("# revocation scenario artifact: " + p.name + "\nseed:" + p.seed + "\n")
		arts = append(arts, revocationArtifact{
			name: p.name, body: body, signer: p.signer, builderID: p.builderID,
			signedAt: p.signedAt, deps: deps, tsaAt: p.tsaAt,
		})
	}

	type attRef struct {
		ArtifactName string   `json:"artifactName"`
		Attestation  string   `json:"attestation"`
		Timestamps   []string `json:"timestamps,omitempty"`
	}
	expected := map[string]string{}
	var refs []attRef

	for _, a := range arts {
		writeFile(filepath.Join(artDir, a.name), a.body, 0o644)
		sum := sha256.Sum256(a.body)
		artSHA := hex.EncodeToString(sum[:])

		subjects := []attestation.Subject{{
			Name: a.name, Digest: map[string]string{"sha256": artSHA},
		}}
		var resolved []map[string]any
		for _, d := range a.deps {
			resolved = append(resolved, map[string]any{
				"name":   d.name,
				"digest": map[string]string{"sha256": d.sha},
			})
		}
		st := buildRevocationStatement(a.name, artSHA, a.builderID, a.signedAt, resolved)
		_ = subjects
		env, err := attestation.SignStatement(a.signer.priv, st)
		must(err)
		attPath := "att-" + a.name + ".json"
		writeJSON(filepath.Join(attDir, attPath), env)

		envBytes := mustMarshalIndent(env)
		envCanonical, err := attestation.CanonicalEnvelopeSHA256(envBytes)
		must(err)
		envSHA := envCanonical

		var tsFiles []string
		if a.tsaAt != nil {
			ev, err := timestampevidence.Sign(tsa.priv, envSHA, *a.tsaAt)
			must(err)
			tsPath := "ts-" + a.name + ".json"
			writeJSON(filepath.Join(tsDir, tsPath), ev)
			tsFiles = append(tsFiles, filepath.ToSlash(
				filepath.Join("revocation", "timestamps", tsPath)))
		}
		refs = append(refs, attRef{
			ArtifactName: a.name,
			Attestation:  filepath.ToSlash(filepath.Join("revocation", "attestations", attPath)),
			Timestamps:   tsFiles,
		})
	}

	expected["root-good-1.0.tar.gz"] = "unaffected"
	expected["root-orphan-1.0.tar.gz"] = "affected"
	expected["root-insufficient-1.0.tar.gz"] = "insufficient"
	expected["downstream-once-1.0.tar.gz"] = "unaffected"
	expected["downstream-twice-a-1.0.tar.gz"] = "unaffected"
	expected["downstream-twice-b-1.0.tar.gz"] = "unaffected"
	expected["downstream-propagated-1.0.tar.gz"] = "affected"
	expected["downstream-of-affected-1.0.tar.gz"] = "affected"
	expected["independent-1.0.tar.gz"] = "unaffected"

	pubPEM, err := cryptokit.MarshalPublicPEM(compromised.pub)
	must(err)
	feed := map[string]any{
		"name":    "scbverify demo revocation feed",
		"version": 3,
		"events": []map[string]any{{
			"keyId":         compromised.id,
			"compromisedAt": rfc3339(revCompromised),
			"revokedAt":     rfc3339(revRevoked),
			"reason":        "演示：CI 构建签名密钥疑似泄露",
			"publicKeyPem":  string(pubPEM),
		}},
	}
	writeJSON(filepath.Join(outDir, "revocation-feed.json"), feed)

	manifest := map[string]any{
		"name":                   revocationScenarioName,
		"compromisedKeyId":       compromised.id,
		"unrevokedKeyId":         secondary.id,
		"tsaKeyId":               tsa.id,
		"compromisedAt":          rfc3339(revCompromised),
		"revokedAt":              rfc3339(revRevoked),
		"revocationFeedVersion":  3,
		"feedFile":               "revocation/revocation-feed.json",
		"evidence":               refs,
		"expectedClassification": expected,
		"gateNote":               "实时下载闸门：所有用被撤销密钥签名的证据一律 deny（时间证据不放行）",
		"historyNote":            "历史复核区分 unaffected / insufficient / affected；自报 metadata 时间不可信",
	}
	writeJSON(filepath.Join(outDir, "revocation-scenario.json"), manifest)
	return manifest
}

func buildRevocationStatement(targetName, targetSHA, builderID string, signedAt time.Time,
	resolved []map[string]any) *attestation.Statement {
	bd := map[string]any{
		"buildType": "https://build.example.com/buildtypes/reproducible-v1",
		"externalParameters": map[string]any{
			"source": map[string]any{
				"uri":    allowedSource,
				"digest": map[string]string{"sha1": allowedCommit},
			},
		},
	}
	if len(resolved) > 0 {
		bd["resolvedDependencies"] = resolved
	}
	return &attestation.Statement{
		Type: "https://in-toto.io/Statement/v1",
		Subject: []attestation.Subject{{
			Name:   targetName,
			Digest: map[string]string{"sha256": targetSHA},
		}},
		PredicateType: attestation.SLSAProvenanceType,
		Predicate: mustJSON(map[string]any{
			"buildDefinition": bd,
			"runDetails": map[string]any{
				"builder": map[string]any{"id": builderID},
				"metadata": map[string]any{
					// 自报时间：仅留证，历史复核不得据此判定。
					"startedOn":  rfc3339(signedAt.Add(-4 * time.Minute)),
					"finishedOn": rfc3339(signedAt),
				},
			},
		}),
	}
}

func ptrTime(t time.Time) *time.Time { return &t }
