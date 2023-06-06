package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/tidwall/gjson"
)

var model *RexService
var tsc *TscService
var projectID = 39
var hostGroupID = 19

func getHosts() (map[string]string, error) {
	hosts := make(map[string]string, 0)
	res, err := model.Call("get_host_group_items_v4", map[string]any{
		"project_id":    projectID,
		"host_group_id": hostGroupID,
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

type Vuln struct {
	Name     string   `json:"name"`
	PluginID int64    `json:"id"`
	Severity string   `json:"severity"`
	IPs      []string `json:"ips"`
}

func parseVulns(data []byte) []Vuln {
	vulns := make([]Vuln, 0)
	res := gjson.GetBytes(data, "response.results")
	for _, d := range res.Array() {
		var v Vuln
		name := d.Get("name")
		id := d.Get("pluginID")
		severity := d.Get("severity.description")
		t := d.Get("hosts.#.iplist")
		ips := make([]string, 0)
		for _, p := range t.Array() {
			m := strings.Split(p.String(), ",")
			for _, n := range m {
				ips = append(ips, n)
			}
		}
		v.Name = name.String()
		v.PluginID = id.Int()
		v.Severity = severity.String()
		v.IPs = ips
		vulns = append(vulns, v)
	}
	return vulns
}

func tagHosts(hosts []string, key, value string) (map[string]any, error) {
	res, err := model.First("upsert_host_tag", map[string]any{
		"host_id":        hosts[0],
		"project_id":     projectID,
		"host_tag_key":   key,
		"host_tag_value": value,
	})
	return res, err
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
	// debug := os.Getenv("DEBUG")
	model = NewRexService(
		rexURL,
		rexUser,
		rexPass,
	)
	if model == nil {
		panic("model error")
	}
	h, err := getHosts()
	if err != nil {
		panic(err)
	}
	hosts := make([]string, 0)
	for _, v := range h {
		hosts = append(hosts, v)
	}
	if len(hosts) == 0 {
		panic("no hosts")
	}
	tsc = NewTscService(
		tscURL,
		tscKey,
		tscSecret,
	)
	d, err := getVulns(st)
	vulns := parseVulns(d)
	for _, vuln := range vulns {
		k := fmt.Sprintf("vuln:%d:name", vuln.PluginID)
		v := vuln.Name
		ids := make([]string, 0)
		for _, ip := range vuln.IPs {
			id, ok := h[ip]
			if !ok {
				continue
			}
			ids = append(ids, id)
		}
		if len(ids) == 0 {
			continue
		}
		_, err := tagHosts(ids, k, v)
		if err != nil {
			panic(err)
		}
	}
	g, err := json.Marshal(vulns)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(g))
}
