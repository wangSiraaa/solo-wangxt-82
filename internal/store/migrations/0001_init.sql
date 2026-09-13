-- 核验服务持久化结构（PostgreSQL）。
-- 一个产物可关联多份证明（attestations 1:N），证明之间即便结论冲突也
-- 全部保留，供人工复核（不在写入端去重或“以新盖旧”）。

CREATE TABLE IF NOT EXISTS artifacts (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name            TEXT NOT NULL,
    sha256          TEXT NOT NULL,
    size_bytes      BIGINT NOT NULL,
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (name, sha256)
);

CREATE TABLE IF NOT EXISTS policies (
    policy_id       TEXT NOT NULL,
    policy_version  TEXT NOT NULL,
    content_sha256  TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (policy_id, policy_version)
);

CREATE TABLE IF NOT EXISTS attestations (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    artifact_id         BIGINT NOT NULL REFERENCES artifacts(id),
    -- envelope_json 是原始 DSSE 信封，原样留证（不做规范化覆盖）。
    envelope_json       JSONB NOT NULL,
    envelope_keyid      TEXT NOT NULL DEFAULT '',
    accepted_key_id     TEXT NOT NULL DEFAULT '',
    -- 证据冲突时不覆盖：同信封内容也允许重复入库，只标记来源。
    received_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    source_ref          TEXT NOT NULL DEFAULT 'unknown'
);

CREATE INDEX IF NOT EXISTS idx_attestations_artifact ON attestations(artifact_id);

CREATE TABLE IF NOT EXISTS verifications (
    id                      BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    artifact_id             BIGINT NOT NULL REFERENCES artifacts(id),
    decision                TEXT NOT NULL CHECK (decision IN ('allow','deny','needs_review')),
    decision_reason         TEXT NOT NULL DEFAULT '',
    -- 三件事分别留痕
    signature_valid         BOOLEAN NOT NULL,
    issuer_trusted          BOOLEAN NOT NULL,
    policy_allowed          BOOLEAN NOT NULL,
    digest_match            BOOLEAN NOT NULL,
    -- 判定版本
    policy_id               TEXT NOT NULL,
    policy_version          TEXT NOT NULL,
    policy_content_sha256   TEXT NOT NULL,
    trust_root_version      INTEGER NOT NULL,
    evaluated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    detail_json             JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_verifications_artifact ON verifications(artifact_id);
CREATE INDEX IF NOT EXISTS idx_verifications_decision ON verifications(decision);

CREATE TABLE IF NOT EXISTS verification_attestations (
    verification_id     BIGINT NOT NULL REFERENCES verifications(id) ON DELETE CASCADE,
    attestation_id      BIGINT NOT NULL REFERENCES attestations(id),
    -- 该证明在本次判定中的逐项结论快照
    signature_valid     BOOLEAN NOT NULL,
    issuer_trusted      BOOLEAN NOT NULL,
    policy_allowed      BOOLEAN NOT NULL,
    digest_match        BOOLEAN NOT NULL,
    conflict_with       BIGINT[],
    PRIMARY KEY (verification_id, attestation_id)
);
