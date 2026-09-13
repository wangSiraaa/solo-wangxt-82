// verifyctl 是演示用命令行客户端：把本地产物与一份/多份 DSSE 证明
// 发送给 scbverify 服务，并以退出码表达结论（allow=0, needs_review=2, deny=3）。
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
)

type attestationItem struct {
	SourceRef    string          `json:"sourceRef"`
	EnvelopeJSON json.RawMessage `json:"envelopeJson"`
}

type request struct {
	ArtifactName string            `json:"artifactName"`
	ArtifactPath string            `json:"artifactPath"`
	Attestations []attestationItem `json:"attestations"`
}

func main() {
	var (
		serverURL = flag.String("url", "http://127.0.0.1:8080", "scbverify 服务地址")
		name      = flag.String("name", "", "产物名称（需与 statement subject 对应）")
		path      = flag.String("file", "", "本地产物路径")
		source    = flag.String("source", "demo-cli", "证据来源标签")
	)
	flag.Parse()
	if *name == "" || *path == "" || flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "用法: verifyctl -name <产物名> -file <产物路径> [attestation.json ...]")
		os.Exit(64)
	}

	req := request{ArtifactName: *name, ArtifactPath: *path}
	for _, f := range flag.Args() {
		raw, err := os.ReadFile(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "读取证据失败: %v\n", err)
			os.Exit(66)
		}
		req.Attestations = append(req.Attestations, attestationItem{SourceRef: *source, EnvelopeJSON: raw})
	}

	body, _ := json.MarshalIndent(req, "", "  ")
	resp, err := http.Post(*serverURL+"/v1/verify", "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "请求服务失败: %v\n", err)
		os.Exit(69)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	var pretty bytes.Buffer
	if json.Indent(&pretty, respBody, "", "  ") == nil {
		fmt.Println(pretty.String())
	} else {
		fmt.Println(string(respBody))
	}

	var out struct {
		Decision string `json:"decision"`
	}
	_ = json.Unmarshal(respBody, &out)
	switch out.Decision {
	case "allow":
		os.Exit(0)
	case "needs_review":
		os.Exit(2)
	default:
		if resp.StatusCode == http.StatusOK {
			os.Exit(3)
		}
		os.Exit(3)
	}
}
