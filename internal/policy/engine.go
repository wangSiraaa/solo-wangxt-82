// Package policy 使用 Open Policy Agent（成熟的开源策略引擎）执行明确写出的
// Rego 信任策略。默认拒绝：只有策略显式 allow 时才算通过。
package policy

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
)

//go:embed trust_policy_embed.rego
var embeddedPolicy string

// DefaultPolicyID / DefaultPolicyVersion 必须与 Rego 中的 policy_meta 一致。
const (
	DefaultPolicyID      = "scb-provenance-policy"
	DefaultPolicyVersion = "2026.09"
)

// StatementInput 是送给 OPA 的声明侧事实（已解析、已规范化）。
type StatementInput struct {
	PredicateType string     `json:"predicate_type"`
	BuilderID     string     `json:"builder_id"`
	Source        SourceFact `json:"source"`
}

// SourceFact 是来源仓库事实。
type SourceFact struct {
	URI    string            `json:"uri"`
	Digest map[string]string `json:"digest"`
}

// PreconditionsInput 是前两道闸门的布尔结论，作为事实喂给策略，
// 但三者的原始结论仍分别返回。
type PreconditionsInput struct {
	SignatureValid     bool `json:"signature_valid"`
	IssuerTrusted      bool `json:"issuer_trusted"`
	DigestMatch        bool `json:"digest_match"`
	PayloadTypeCorrect bool `json:"payload_type_correct"`
}

// Input 是 OPA 输入全集。
type Input struct {
	Statement StatementInput     `json:"statement"`
	Policy    PreconditionsInput `json:"policy"`
	// Now 是评估时间（RFC3339），由调用方传入以便演示向量可重复。
	Now string `json:"now"`
}

// Result 是“声明符合策略”这一件事的独立结论。
type Result struct {
	Allowed       bool     `json:"allowed"`
	PolicyID      string   `json:"policyId"`
	PolicyVersion string   `json:"policyVersion"`
	Violations    []string `json:"violations"`
	Reason        string   `json:"reason,omitempty"`
}

// Engine 封装已编译的 Rego 策略。
type Engine struct {
	module   string
	policyID string
	version  string
	compiled bool
}

// LoadEngine 从 .rego 文件加载并编译策略。
func LoadEngine(regoPath string) (*Engine, error) {
	data, err := os.ReadFile(regoPath)
	if err != nil {
		return nil, fmt.Errorf("policy: 读取策略文件 %q: %w", regoPath, err)
	}
	return newEngine(string(data))
}

// EmbeddedEngine 返回随二进制内嵌的默认策略引擎。
func EmbeddedEngine() (*Engine, error) {
	return newEngine(embeddedPolicy)
}

func newEngine(module string) (*Engine, error) {
	e := &Engine{module: module, policyID: DefaultPolicyID, version: DefaultPolicyVersion}
	if err := e.compile(); err != nil {
		return nil, err
	}
	return e, nil
}

// ID / Version 返回策略标识，随判定记录持久化。
func (e *Engine) ID() string      { return e.policyID }
func (e *Engine) Version() string { return e.version }

// Module 返回策略模块原文（用于计算内容指纹）。
func (e *Engine) Module() string { return e.module }

func (e *Engine) compile() error {
	// 提前编译，语法错误在启动时暴露，而不是首次请求时。
	compiled, err := ast.CompileModules(map[string]string{"trust_policy.rego": e.module})
	if err != nil {
		return fmt.Errorf("policy: Rego 编译错误: %w", err)
	}
	// 从 Rego policy_meta 读取策略标识与版本，避免 Go 常量与策略内容漂移。
	readMeta := func(key string) string {
		mod := compiled.Modules["trust_policy.rego"]
		if mod == nil {
			return ""
		}
		var rule *ast.Rule
		for _, r := range mod.Rules {
			if r.Head.Name == "policy_meta" {
				rule = r
				break
			}
		}
		if rule == nil || rule.Head == nil {
			return ""
		}
		// Head.Value 是 { "policy_id": "...", "policy_version": "..." }
		t, ok := rule.Head.Value.Value.(ast.Object)
		if !ok {
			return ""
		}
		v := t.Get(ast.StringTerm(key))
		if v == nil {
			return ""
		}
		s, ok := v.Value.(ast.String)
		if !ok {
			return ""
		}
		return string(s)
	}
	if id := readMeta("policy_id"); id != "" {
		e.policyID = id
	}
	if ver := readMeta("policy_version"); ver != "" {
		e.version = ver
	}
	e.compiled = true
	return nil
}

// Evaluate 在给定时间点评估策略。
func (e *Engine) Evaluate(ctx context.Context, in Input, now time.Time) (Result, error) {
	if !e.compiled {
		return Result{}, errorsNew("policy: 策略未编译")
	}
	in.Now = now.UTC().Format(time.RFC3339)

	r := rego.New(
		rego.Query("data.scbverify"),
		rego.Module("trust_policy.rego", e.module),
		rego.Input(in),
	)
	rs, err := r.Eval(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("policy: OPA 评估失败: %w", err)
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return Result{}, fmt.Errorf("policy: OPA 未返回任何结论（未定义即拒绝）")
	}

	obj, ok := rs[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		return Result{}, fmt.Errorf("policy: OPA 结论类型异常: %T", rs[0].Expressions[0].Value)
	}

	res := Result{PolicyID: e.policyID, PolicyVersion: e.version, Violations: []string{}}
	if allow, _ := obj["allow"].(bool); allow {
		res.Allowed = true
	}
	if vs, ok := obj["violation"].([]interface{}); ok {
		for _, v := range vs {
			if s, ok := v.(string); ok {
				res.Violations = append(res.Violations, s)
			}
		}
	}
	if !res.Allowed {
		if len(res.Violations) == 0 {
			res.Reason = "策略默认拒绝（未满足 allow，且无具体违规项）"
		} else {
			res.Reason = "策略拒绝：" + strings.Join(res.Violations, "; ")
		}
	}
	return res, nil
}

// errorsNew 避免在文件顶部仅为一处引入 errors。
func errorsNew(s string) error { return fmt.Errorf("%s", s) }
