package main

import (
	"flag"
	"fmt"
	"os"
)

var model *RexService
var tsc *TscService

func getHosts() (map[string]string, error) {
	hosts := make(map[string]string, 0)
	res, err := model.Call("get_host_group_items_v4", map[string]any{
		"project_id":    39,
		"host_group_id": 19,
	})
	if err != nil {
		return hosts, err
	}
	for _, x := range res {
		hostID := x["host_id"].(string)
		hostIP := x["host_ip"].(string)
		hosts[hostIP] = hostID
	}
	return hosts, err
}

func getVulns(sourceType string) ([]byte, error) {
	opts := map[string]any{
		"query": map[string]any{
			"tool":        "vulnipsummary",
			"endOffset":   1000,
			"startOffset": 0,
			"type":        "vuln",
			"filters":     []any{},
		},
		"type":       "vuln",
		"sourceType": sourceType,
	}
	d, err := tsc.Post("/analysis", opts, nil)
	return d, err
}

func main() {
	var st string
	flag.StringVar(&st, "source-type", "", "source type: cumulative or patched")
	flag.Parse()
	if st == "" {
		st = "patched"
	}
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
	hosts, err := getHosts()
	if err != nil {
		panic(err)
	}
	if hosts == nil {
		panic("cannot get hosts")
	}
	tsc = NewTscService(
		tscURL,
		tscKey,
		tscSecret,
	)
	d, err := getVulns(st)
	fmt.Println(string(d))
}
