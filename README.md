# scbverify — 软件供应链构建产物核验服务（纯后端）

在**下载构建产物之前**，验证它是否来自允许的源码与构建流程。服务只读取
本地产物的字节并计算摘要，**任何路径（含失败路径）都不会执行、解压或
反序列化产物内容**。

## 核验模型：三件事 + 一道硬闸门，分别给结论

一次核验对每份证明（attestation）独立返回四个维度，互不掩盖：

| 维度 | 由谁判定 | 依据 |
|---|---|---|
| **签名有效** `signature.valid` | Go + `go-securesystemslib` DSSE + `crypto/ed25519` | DSSE PAE 重放保护、Ed25519 密码学验签；KeyID 由服务端按公钥 DER(SPKI) 的 SHA-256 自行计算，**不信信封自报 keyid** |
| **签发者可信** `issuer.trusted` | 显式信任根 JSON | 验签通过的公钥指纹必须在信任根中，且其绑定的 `issuer` 与 provenance 自报 `runDetails.builder.id` 完全一致 |
| **声明符合策略** `policy.allowed` | **OPA**（Rego，默认拒绝） | 谓词类型、允许的构建者白名单、允许的源码仓库精确匹配、commit 固定、策略生效窗口（**过期即拒绝**） |
| **摘要与实际字节一致** `digest.matched` | Go `crypto/sha256` 流式重算 | 只对 statement 中**名称等于请求 `artifactName` 的 subject** 重算并逐一比对（如同一份声明还附带 `sbom.json` 等其他 subject，它们不参与本次目标产物比对，仅在 `digest.ignoredSubjects` 留名）；目标 subject 缺失或摘要不一致都 `hardReject=true`，**直接拒绝，不只检查 JSON 字段是否齐全** |

典型分离场景：

- **被改过的文件**：签名仍有效（签名保护的是声明），但重算摘要对不上 →
  硬拒绝。
- **不受信任构建者**：其密钥若已登记为“已知但不受信任”，签名密码学上
  有效（结论一为真），但信任判定（结论二）与策略（结论三）独立为假。
- **过期策略**：签名与信任都成立，OPA 因生效窗口过期独立拒绝。

最终决策：

- `allow`：至少一份证明四关全过，且证据间无冲突；
- `needs_review`：存在多份四关全过但互相矛盾的证据（如 builder/source
  固定版本不同），**冲突证据全部保留**，转人工复核；
- `deny`：其余情况（摘要硬拒绝优先级最高）。

## 证据与判定版本持久化（PostgreSQL）

- `artifacts`：产物名 + SHA-256 + 大小（不存内容）；
- `attestations`：每份 DSSE 信封原文，无论成功失败或是否冲突都原样保留
  （1 个产物 N 份证明，不去重、不以新盖旧）；
- `verifications`：判定结果 + 四个布尔维度 + `policy_id`、
  `policy_version`、策略内容 SHA-256、信任根版本 + 完整判定快照 JSONB；
- `verification_attestations`：本次判定中每份证明的逐项快照与
  `conflict_with` 冲突对象数组。

未配置 PostgreSQL 时使用语义一致的内存存储（便于离线测试）。

## 目录结构

```
cmd/server/         HTTP 核验服务
cmd/verifyctl/      演示用命令行客户端
cmd/genvectors/     确定性测试向量生成器
internal/attestation/  DSSE v1 信封解析与 Ed25519 验签、in-toto Statement 解析
internal/cryptokit/    Ed25519 密钥/PEM/指纹
internal/trust/        信任根加载与“签发者可信”判定
internal/policy/       OPA Rego 引擎（默认拒绝、版本化、生效窗口）
internal/artifact/     实际产物流式哈希与摘要硬比对
internal/verifier/     四关编排、冲突检测、事务化持久化
internal/store/        Store 接口 + 内存实现 + PostgreSQL/pgx 实现与迁移
internal/api/          /v1/verify 等 HTTP 接口
policies/trust_policy.rego
test/e2e/             端到端与“产物绝不执行”安全测试
demo/                 由 genvectors 生成：密钥、产物、证明、过期策略、期望清单
```

## 快速开始

需要 Go 1.23+（会自动按 go.mod 切换工具链）。

```bash
# 1) 生成可重复的演示向量（固定 seed 的 Ed25519，输出逐字节稳定）
go run ./cmd/genvectors --out demo

# 2) 跑全部测试（含失败路径与“不执行产物”行为/静态测试）
go test ./... -count=1

# 3a) 内存存储启动
go run ./cmd/server \
  -trust-root demo/trustroot.json \
  -policy policies/trust_policy.rego \
  -known-keys demo/keys/known-untrusted.pub.pem

# 3b) 或使用 PostgreSQL
# 先在本机设置自己的开发数据库变量（不要把真实值写入仓库）：
# export SCBVERIFY_DB_USER=REPLACE_ME
# export SCBVERIFY_DB_PASSWORD=REPLACE_ME
# export SCBVERIFY_DB_NAME=scbverify
docker compose -f deploy/docker-compose.yml up -d postgres
# export SCBVERIFY_PG_DSN='postgres://REPLACE_ME:REPLACE_ME@127.0.0.1:5432/scbverify?sslmode=disable'
go run ./cmd/server \
  -trust-root demo/trustroot.json \
  -policy policies/trust_policy.rego \
  -known-keys demo/keys/known-untrusted.pub.pem \
  -pg-dsn "$SCBVERIFY_PG_DSN"

# 4) 核验
go run ./cmd/verifyctl -name payments-api-1.4.2.tar.gz \
  -file demo/artifacts/payments-api-1.4.2.tar.gz \
  demo/attestations/01-valid.attestation.json      # exit 0 = allow
```

`verifyctl` 退出码：`0=allow`，`2=needs_review`，`3=deny`。

## 可重复的验签向量

`demo/expected_vectors.json` 由 `genvectors` 确定性生成：

- 密钥由固定 32 字节 seed 派生（Ed25519 签名确定性），重新生成逐字节一致；
- 每条向量记录信封 SHA-256、签名 base64、实际/声明摘要，以及当前策略与
  过期策略下的预期四维度布尔值与最终决策；
- `test/e2e/manifest_test.go` 会对每条向量做**真实核验**并与清单逐项比对。

| 向量文件 | 覆盖的失败路径 |
|---|---|
| `02-tampered-file.attestation.json` | 实际文件被改 1 字节：摘要硬拒绝 |
| `03-untrusted-builder.attestation.json` | 不受信任构建者：签名有效 / 信任独立失败 |
| `04-expired-policy.attestation.json` | 配合 `demo/policies/trust_policy.expired.rego`：策略过期拒绝 |
| `05-wrong-source.attestation.json` | 源码不在允许列表（签名、信任仍成立） |
| `06-digest-field-mismatch.attestation.json` | JSON 字段齐全但摘要值伪造：必须重算并拒绝 |
| `07-conflicting-commit.attestation.json` | 与 01 同时提交：证据冲突 → needs_review 且全部留证 |
| `08-target-plus-valid-sbom.attestation.json` | 同声明含目标 tar.gz 与摘要正确的 sbom.json：只比较目标 subject，必须 allow（其他 subject 不影响目标产物） |
| （测试内构造） | 翻转签名首字节：签名维度独立失败；声明只有 sbom.json 而缺目标 subject：明确拒绝 |

## HTTP API

`POST /v1/verify`

```json
{
  "artifactName": "payments-api-1.4.2.tar.gz",
  "artifactPath": "/data/payments-api-1.4.2.tar.gz",
  "attestations": [
    {"sourceRef": "ci-primary", "envelopeJson": {"payloadType": "...", "payload": "...", "signatures": [{"keyid": "...", "sig": "..."}]}}
  ]
}
```

响应中 `results[]` 每项含 `signature / issuer / policy / digest` 四个独立
结论；顶层 `decision` 为汇总决策。查询历史证据：

- `GET /v1/artifacts/attestations?name=...&sha256=...`
- `GET /v1/artifacts/verifications?name=...&sha256=...`

## 演示安全边界说明

- 仅使用本地生成的 Ed25519 测试密钥（PEM），**不依赖任何商业证书服务**；
  `demo/keys/*.priv.pem` 权限 0600，仅用于重新生成向量，服务运行只需
  信任根中的公钥。
- 产物处理只使用 `os.Open` + `io.Copy(sha256.New(), ...)`：`internal/`
  下静态禁止导入 `os/exec`、`syscall`（有测试守护），且有“可执行脚本
  形状产物 + 哨兵文件”的行为测试，证明放行与所有失败路径均不执行内容。
- 这是教学/评审级演示：生产化还需补充请求鉴权、路径白名单隔离、
  DSSE 多签阈值、密钥轮换与信任根签名分发等。
