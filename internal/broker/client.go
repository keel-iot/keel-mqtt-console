package broker

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	base string
	http *http.Client
}

func New(base string) *Client {
	return &Client{base: strings.TrimRight(base, "/"), http: &http.Client{Timeout: 10 * time.Second}}
}

func (c *Client) Do(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	if !allowed(path, method) {
		return nil, fmt.Errorf("broker path is not exposed by the console")
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.http.Do(req)
}

func allowed(path, method string) bool {
	path = strings.SplitN(path, "?", 2)[0]
	reads := map[string]bool{
		"/api/cluster/nodes": true, "/api/cluster/routes": true, "/api/cluster/sessions": true,
		"/api/cluster/session-inventory": true,
		"/api/metrics": true, "/api/live/clients": true, "/api/acl/roles": true,
		"/api/acl/bindings": true, "/api/acl/rulesets": true,
	}
	if method == http.MethodGet {
		return reads[path]
	}
	if strings.HasPrefix(path, "/api/acl/roles") || strings.HasPrefix(path, "/api/acl/bindings") || strings.HasPrefix(path, "/api/acl/rulesets") {
		return method == http.MethodPost || method == http.MethodDelete
	}
	return false
}

func JSONBody(data []byte) io.Reader { return bytes.NewReader(data) }
