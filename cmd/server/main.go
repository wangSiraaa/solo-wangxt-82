// scbverify 服务入口：加载信任根、OPA 策略与存储，启动纯后端 HTTP API。
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"scbverify/internal/api"
	"scbverify/internal/cryptokit"
	"scbverify/internal/policy"
	"scbverify/internal/store"
	"scbverify/internal/trust"
	"scbverify/internal/verifier"
)

func main() {
	var (
		addr          = flag.String("addr", ":8080", "HTTP 监听地址")
		trustRoot     = flag.String("trust-root", "demo/trustroot.json", "信任根 JSON 路径")
		regoPath      = flag.String("policy", "policies/trust_policy.rego", "Rego 策略文件路径")
		pgDSN         = flag.String("pg-dsn", os.Getenv("SCBVERIFY_PG_DSN"), "PostgreSQL DSN；为空则使用内存存储")
		knownKeyFiles = flag.String("known-keys", "", "额外的“已知但不受信任”PEM 公钥，逗号分隔")
		useEmbedded   = flag.Bool("embedded-policy", false, "使用二进制内嵌策略（忽略 -policy）")
	)
	flag.Parse()

	root, err := trust.LoadRoot(*trustRoot)
	if err != nil {
		log.Fatalf("加载信任根失败: %v", err)
	}
	for _, kf := range strings.Split(*knownKeyFiles, ",") {
		kf = strings.TrimSpace(kf)
		if kf == "" {
			continue
		}
		pub, err := cryptokit.LoadPublicPEMFile(kf)
		if err != nil {
			log.Fatalf("加载已知公钥 %s 失败: %v", kf, err)
		}
		if err := root.AddKnownButUntrustedKey(pub); err != nil {
			log.Fatalf("登记已知公钥 %s 失败: %v", kf, err)
		}
		log.Printf("已登记已知但不受信任的公钥: %s", kf)
	}

	var engine *policy.Engine
	if *useEmbedded {
		engine, err = policy.EmbeddedEngine()
	} else {
		engine, err = policy.LoadEngine(*regoPath)
	}
	if err != nil {
		log.Fatalf("加载 OPA 策略失败: %v", err)
	}

	ctx := context.Background()
	var st store.Store
	if *pgDSN != "" {
		pg, err := store.NewPostgresStore(ctx, *pgDSN)
		if err != nil {
			log.Fatalf("连接 PostgreSQL 失败: %v", err)
		}
		st = pg
		log.Printf("已连接 PostgreSQL 并完成迁移")
	} else {
		st = store.NewMemoryStore()
		log.Printf("未提供 -pg-dsn，使用内存存储（重启数据丢失）")
	}
	defer st.Close()

	v := verifier.New(root, engine, st, nil)
	srv := &http.Server{
		Addr:              *addr,
		Handler:           api.NewServer(v, st),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		log.Printf("scbverify 监听 %s（策略 %s@%s，信任根 v%d）",
			*addr, engine.ID(), engine.Version(), root.Version)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP 服务错误: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	log.Printf("已优雅退出")
}
