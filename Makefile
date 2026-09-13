.PHONY: vectors test vet fmt demo-server demo memory-test

vectors: ## 生成（并可复现刷新）演示向量
	go run ./cmd/genvectors --out demo

test: ## 运行全部测试
	go test ./... -count=1

vet: ## 静态检查
	go vet ./...

fmt: ## 格式化并同步内嵌策略
	gofmt -w cmd internal test
	cp policies/trust_policy.rego internal/policy/trust_policy_embed.rego

demo-server: ## 内存存储启动演示服务
	go run ./cmd/server -trust-root demo/trustroot.json \
	  -policy policies/trust_policy.rego \
	  -known-keys demo/keys/known-untrusted.pub.pem

demo: ## 对运行中的服务跑演示（默认 http://127.0.0.1:8080）
	scripts/demo.sh $(or $(URL),http://127.0.0.1:8080)
