package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

type TscService struct {
	Client  *http.Client
	BaseURL string
	Key     string
	Secret  string
}

func NewTscService(url string, key string, secret string) *TscService {
	return &TscService{
		Client:  &http.Client{},
		BaseURL: url,
		Key:     key,
		Secret:  secret,
	}
}

func (t *TscService) Post(route string, opts map[string]any, query map[string]string) (res []byte, err error) {
	var h string
	h = "{}"
	if opts != nil {
		tp, err := json.Marshal(opts)
		if err != nil {
			return res, errors.New("cannot convert opts to json")
		}
		h = string(tp)
	}
	rawUrl := fmt.Sprintf("%s/rest%s", t.BaseURL, route)
	u, err := url.Parse(rawUrl)
	if query != nil {
		q := u.Query()
		for k, v := range query {
			q.Set(k, v)
		}
		u.RawQuery = q.Encode()
	}
	d := bytes.NewBuffer([]byte(h))
	req, err := http.NewRequest("POST", u.String(), d)
	req.Header.Set("Content-Type", "application/json")
	apiHeader := fmt.Sprintf("accesskey=%s; secretkey=%s;", t.Key, t.Secret)
	req.Header.Set("x-apikey", apiHeader)
	resp, err := t.Client.Do(req)
	if err != nil {
		return res, err
	}
	defer resp.Body.Close()
	res, err = io.ReadAll(resp.Body)
	return res, err
}

type RexService struct {
	Client  *http.Client
	BaseURL string
	User    string
	Pass    string
}

func NewRexService(url string, user string, pass string) *RexService {
	return &RexService{
		Client:  &http.Client{},
		BaseURL: url,
		User:    user,
		Pass:    pass,
	}
}

func (r *RexService) Call(fn string, opts map[string]any) ([]map[string]any, error) {
	var t string
	res := make([]map[string]any, 0)
	t = "{}"
	if opts != nil {
		tp, err := json.Marshal(opts)
		if err != nil {
			return res, errors.New("cannot convert opts to json")
		}
		t = string(tp)
	}
	url := fmt.Sprintf("%s/rpc/%s", r.BaseURL, fn)
	d := bytes.NewBuffer([]byte(t))
	req, err := http.NewRequest("POST", url, d)
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(r.User, r.Pass)
	resp, err := r.Client.Do(req)
	if err != nil {
		return res, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return res, err
	}
	if resp.StatusCode != 200 {
		return res, errors.New(string(body))
	}
	err = json.Unmarshal(body, &res)
	return res, err
}

func (r *RexService) First(sp string, opts map[string]any) (row map[string]any, err error) {
	rows, err := r.Call(sp, opts)
	if err != nil {
		return row, err
	}
	if len(rows) == 0 {
		return row, err
	}
	row = rows[0]
	return row, err
}
