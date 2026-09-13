package store

import "encoding/json"

// jsonUnmarshal 统一 JSON 解析入口，便于在内存/PG 实现中共用。
func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
