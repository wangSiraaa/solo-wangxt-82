// scbverify 服务入口：加载信任根、OPA 策略、撤销清单与存储，启动纯后端 HTTP API。
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
	"scbverify/internal/review"
	"scbverify/internal/revocation"
	"scbverify/internal/store"
	"scbverify/internal/trust"
	"scbverify/internal/verifier"
)

func main() {
	var (
		addr           = flag.String("addr", ":8080", "HTTP 监听地址")
		trustRoot      = flag.String("trust-root", "demo/trustroot.json", "信任根 JSON 路径")
		regoPath       = flag.String("policy", "policies/trust_policy.rego", "Rego 策略文件路径")
		pgDSN          = flag.String("pg-dsn", os.Getenv("SCBVERIFY_PG_DSN"), "PostgreSQL DSN；为空则使用内存存储")
		knownKeyFiles  = flag.String("known-keys", "", "额外的“已知但不受信任”PEM 公钥，逗号分隔")
		revocationFeed = flag.String("revocation-feed", "", "密钥撤销清单 JSON 路径（配置后下载闸门 fail-closed）")
		useEmbedded    = flag.Bool("embedded-policy", false, "使用二进制内嵌策略（忽略 -policy）")
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

	var rev *revocation.List
	if *revocationFeed != "" {
		rev, err = revocation.LoadFeed(*revocationFeed)
		if err != nil {
			log.Fatalf("加载撤销清单失败: %v", err)
		}
		// 撤销事件中的公钥也纳入已知公钥（验签可成功，闸门/信任失败）。
		pubs, perr := rev.KnownRevocationPublicKeys()
		if perr != nil {
			log.Fatalf("解析撤销清单公钥失败: %v", perr)
		}
		for _, pub := range pubs {
			_ = root.AddKnownButUntrustedKey(pub)
		}
		// 撤销事件入库，便于查询与留痕。
		log.Printf("已加载撤销清单 %s v%d（%d 个事件）",
			*revocationFeed, rev.Version, len(rev.RevokedKeyIDs()))
	} else {
		log.Printf("未配置 -revocation-feed：下载闸门不做密钥撤销检查")
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

	// 撤销事件幂等入库。
	if rev != nil {
		for _, id := range rev.RevokedKeyIDs() {
			e, _ := rev.EventFor(id)
			rec := store.RevocationEventRecord{KeyID: id, Reason: e.Reason, FeedVersion: rev.Version}
			if t, err := time.Parse(time.RFC3339, e.CompromisedAt); err == nil {
				rec.CompromisedAt = t.UTC()
			}
			if t, err := time.Parse(time.RFC3339, e.RevokedAt); err == nil {
				rec.RevokedAt = t.UTC()
			}
			if err := st.UpsertRevocationEvent(ctx, rec); err != nil {
				log.Fatalf("登记撤销事件失败: %v", err)
			}
		}
	}

	gate := verifier.NewWithRevocation(root, engine, st, rev, nil)
	reviewSvc := review.NewService(st, root, engine, rev, nil)
	srv := &http.Server{
		Addr:              *addr,
		Handler:           api.NewServer(gate, st, reviewSvc, rev),
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
