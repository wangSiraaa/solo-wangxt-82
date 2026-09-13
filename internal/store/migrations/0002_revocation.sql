-- 0002：密钥撤销 / 可信时间证据 / 依赖产物链 / 历史复核记录。
-- 只新增表与列，绝不修改或覆盖 0001 中已保存的原始签名材料与历史判定。

CREATE TABLE IF NOT EXISTS revocation_events (
    key_id          TEXT PRIMARY KEY,
    compromised_at  TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ NOT NULL,
    reason          TEXT NOT NULL DEFAULT '',
    feed_version    INTEGER NOT NULL DEFAULT 0,
    recorded_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS trusted_time_evidence (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    envelope_sha256     TEXT NOT NULL,
    tsa_key_id          TEXT NOT NULL,
    trusted_timestamp   TIMESTAMPTZ NOT NULL,
    -- 证据原文（TSA 签名在内），用于随时复核，且与 DSSE 信封分开保存。
    evidence_json       JSONB NOT NULL,
    received_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (envelope_sha256, tsa_key_id, trusted_timestamp)
);

CREATE INDEX IF NOT EXISTS idx_tte_envelope ON trusted_time_evidence(envelope_sha256);

-- 依赖产物链：由“已签名 provenance 的 resolvedDependencies”提取，
-- 边方向：artifact_id（下游）依赖 dep（被引用的上游输入）。
CREATE TABLE IF NOT EXISTS artifact_dependencies (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    artifact_id     BIGINT NOT NULL REFERENCES artifacts(id),
    attestation_id  BIGINT NOT NULL REFERENCES attestations(id),
    dep_name        TEXT NOT NULL,
    dep_sha256      TEXT NOT NULL,
    recorded_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (artifact_id, attestation_id, dep_name, dep_sha256)
);

CREATE INDEX IF NOT EXISTS idx_deps_artifact ON artifact_dependencies(artifact_id);
CREATE INDEX IF NOT EXISTS idx_deps_dep ON artifact_dependencies(dep_name, dep_sha256);

-- 判定记录扩展：区分实时下载闸门与历史复核，并保留复核引用时间。
ALTER TABLE verifications
    ADD COLUMN IF NOT EXISTS review_kind      TEXT NOT NULL DEFAULT 'gate',
    ADD COLUMN IF NOT EXISTS classification   TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS reference_time   TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS revocation_feed_version INTEGER NOT NULL DEFAULT 0;

-- 复核记录索引（按产物回看历次复核）。
CREATE INDEX IF NOT EXISTS idx_verifications_kind
    ON verifications(review_kind);
