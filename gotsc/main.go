package main

import (
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
