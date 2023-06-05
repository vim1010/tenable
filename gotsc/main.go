package main

import (
	"fmt"
	"os"
)

var model *RexService
var tsc *TscService

func main() {
	rexURL := os.Getenv("REX_BASE_URL")
	rexUser := os.Getenv("REX_USER")
	rexPass := os.Getenv("REX_PASS")
	tscURL := os.Getenv("TSC_URL")
	tscKey := os.Getenv("TSC_KEY")
	tscSecret := os.Getenv("TSC_SECRET")
	model = NewRexService(
		rexURL,
		rexUser,
		rexPass,
	)
	if model == nil {
		panic("model error")
	}
	tsc = NewTscService(
		tscURL,
		tscKey,
		tscSecret,
	)
	opts := map[string]any{
		"query": map[string]any{
			"tool":        "vulnipsummary",
			"endOffset":   1000,
			"startOffset": 0,
			"type":        "vuln",
			"filters":     []any{},
		},
		"type":       "vuln",
		"sourceType": "patched",
	}
	d, err := tsc.Post("/analysis", opts, nil)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(d))
}
