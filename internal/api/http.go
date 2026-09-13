// Package api 提供纯后端 HTTP/JSON 接口。接口只接收“本地产物路径 +
// DSSE 证明 JSON”，服务端对产物只做哈希读取。
package api

import (
	"encoding/json"
	"net/http"

	"scbverify/internal/review"
	"scbverify/internal/revocation"
	"scbverify/internal/store"
	"scbverify/internal/timestampevidence"
	"scbverify/internal/verifier"
)

// Server 持有核验器、复核服务、撤销清单与存储。
type Server struct {
	v       *verifier.Verifier
	st      store.Store
	reviews *review.Service
	rev     *revocation.List
	mux     *http.ServeMux
}

// NewServer 构造路由。
func NewServer(v *verifier.Verifier, st store.Store,
	reviews *review.Service, rev *revocation.List) *Server {
	s := &Server{v: v, st: st, reviews: reviews, rev: rev, mux: http.NewServeMux()}
	s.routes()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	s.mux.HandleFunc("/healthz", s.handleHealth)
	s.mux.HandleFunc("/v1/verify", s.handleVerify)
	s.mux.HandleFunc("/v1/artifacts/", s.handleArtifactSub)
	s.mux.HandleFunc("/v1/revocations", s.handleRevocations)
	s.mux.HandleFunc("/v1/review", s.handleReview)
	s.mux.HandleFunc("/v1/time-evidence", s.handleTimeEvidence)
}

// verifyRequest 是核验请求体。
type verifyRequest struct {
	ArtifactName string `json:"artifactName"`
	ArtifactPath string `json:"artifactPath"`
	Attestations []struct {
		SourceRef    string          `json:"sourceRef"`
		EnvelopeJSON json.RawMessage `json:"envelopeJson"`
	} `json:"attestations"`
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	var req verifyRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求体不是合法 JSON: "+err.Error())
		return
	}
	if req.ArtifactName == "" || req.ArtifactPath == "" {
		writeError(w, http.StatusBadRequest, "artifactName 与 artifactPath 必填")
		return
	}
	if len(req.Attestations) == 0 {
		writeError(w, http.StatusBadRequest, "attestations 至少一份")
		return
	}
	vreq := verifier.Request{ArtifactName: req.ArtifactName, ArtifactPath: req.ArtifactPath}
	for _, a := range req.Attestations {
		vreq.Attestations = append(vreq.Attestations, verifier.AttestationInput{
			SourceRef: a.SourceRef, EnvelopeJSON: a.EnvelopeJSON,
		})
	}
	resp, err := s.v.Verify(r.Context(), vreq)
	if err != nil {
		// 文件读不到等前置错误以 422 返回；这本身不产生判定记录。
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// reviewRequest 请求对一个已入库的历史产物做影响复核。
type reviewRequest struct {
	ArtifactName string `json:"artifactName"`
	ArtifactSHA  string `json:"artifactSha256"`
}

func (s *Server) handleReview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	var req reviewRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求体不是合法 JSON: "+err.Error())
		return
	}
	if req.ArtifactName == "" || req.ArtifactSHA == "" {
		writeError(w, http.StatusBadRequest, "artifactName 与 artifactSha256 必填")
		return
	}
	if s.reviews == nil {
		writeError(w, http.StatusServiceUnavailable, "未配置复核服务（缺少撤销清单）")
		return
	}
	report, err := s.reviews.Review(r.Context(), req.ArtifactName, req.ArtifactSHA)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, report)
}

// timeEvidenceRequest 补入一条 TSA 可信时间证据。
type timeEvidenceRequest struct {
	EnvelopeSHA256 string                                `json:"envelopeSha256"`
	Evidence       timestampevidence.TrustedTimeEvidence `json:"evidence"`
}

func (s *Server) handleTimeEvidence(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	var req timeEvidenceRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求体不是合法 JSON: "+err.Error())
		return
	}
	if req.EnvelopeSHA256 == "" {
		writeError(w, http.StatusBadRequest, "envelopeSha256 必填（应为 DSSE 信封规范化摘要）")
		return
	}
	if s.reviews == nil {
		writeError(w, http.StatusServiceUnavailable, "未配置复核服务（缺少 TSA 信任根）")
		return
	}
	id, err := s.reviews.IngestTimeEvidence(r.Context(), req.EnvelopeSHA256, &req.Evidence)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"storedId": id, "status": "accepted"})
}

func (s *Server) handleRevocations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	if s.rev == nil {
		writeJSON(w, http.StatusOK, map[string]any{"version": 0, "events": []any{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version": s.rev.Version,
		"name":    s.rev.Name,
		"events":  s.rev.RevokedKeyIDs(),
	})
}

func (s *Server) handleArtifactSub(w http.ResponseWriter, r *http.Request) {
	// /v1/artifacts/attestations|verifications?name=...&sha256=...
	q := r.URL.Query()
	name, sha := q.Get("name"), q.Get("sha256")
	if name == "" || sha == "" {
		writeError(w, http.StatusBadRequest, "需要查询参数 name 与 sha256")
		return
	}
	a, err := s.st.GetArtifact(r.Context(), name, sha)
	if err != nil {
		writeError(w, http.StatusNotFound, "产物不存在")
		return
	}
	switch r.URL.Path {
	case "/v1/artifacts/attestations":
		recs, err := s.st.ListAttestations(r.Context(), a.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, recs)
	case "/v1/artifacts/verifications":
		recs, err := s.st.ListVerifications(r.Context(), a.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, recs)
	case "/v1/artifacts/dependencies":
		recs, err := s.st.ListDependencyEdges(r.Context(), a.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, recs)
	default:
		writeError(w, http.StatusNotFound, "未知子路径，使用 /attestations、/verifications 或 /dependencies")
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if err := s.st.Ping(r.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, "存储不可用: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
