// Package push sends SBOMs and workload lists to a Watchpost server (or anything implementing
// the same two endpoints) with an API token.
package push

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultURL is the Watchpost API base.
const DefaultURL = "https://scanradar.site/api"

// Client calls the API.
type Client struct {
	URL       string // API base, e.g. https://scanradar.site/api
	Token     string
	UserAgent string
	HTTP      *http.Client
}

// Counts are a project's open vulnerabilities after an upload.
type Counts struct {
	Total    int `json:"total"`
	KEV      int `json:"kev"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
}

// Result of an upload.
type Result struct {
	Project struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		URL  string `json:"url"`
	} `json:"project"`
	Components int    `json:"components"`
	Counts     Counts `json:"counts"`
	// Failed is set when the fail_on policy matched (the server then answers 422).
	Failed bool `json:"failed"`
}

// ErrPolicy is returned (with the result) when the upload went through but fail_on matched.
var ErrPolicy = errors.New("vulnerabilities match the --fail-on policy")

// Upload sends a CycloneDX JSON document to the project (created on first upload).
// kind is "host", "image" or "app"; failOn "", "kev" or "critical".
func (c *Client) Upload(ctx context.Context, project, kind, failOn string, sbom []byte) (*Result, error) {
	// The project goes in the query: image names contain "/".
	q := url.Values{"project": {project}, "kind": {kind}}
	if failOn != "" {
		q.Set("fail_on", failOn)
	}
	var res Result
	status, err := c.do(ctx, http.MethodPut, "/v1/sbom/upload?"+q.Encode(), sbom, &res)
	if err != nil {
		return nil, err
	}
	if status == http.StatusUnprocessableEntity && res.Failed {
		return &res, ErrPolicy
	}
	return &res, nil
}

// Workload is a container of a Kubernetes workload and the image it runs.
type Workload struct {
	Namespace string `json:"namespace"`
	Kind      string `json:"kind"` // Deployment, StatefulSet, DaemonSet, CronJob, Job, Pod
	Name      string `json:"name"`
	Container string `json:"container"`
	Image     string `json:"image"`  // as written in the pod spec
	Repo      string `json:"repo"`   // repository without tag or digest
	Digest    string `json:"digest"` // sha256:… actually running
	Replicas  int    `json:"replicas"`
}

// Workloads replaces the cluster project's workload list.
func (c *Client) Workloads(ctx context.Context, cluster string, ws []Workload) (int, error) {
	body, err := json.Marshal(map[string]any{"workloads": ws})
	if err != nil {
		return 0, err
	}
	var res struct {
		Workloads int `json:"workloads"`
	}
	_, err = c.do(ctx, http.MethodPut, "/v1/sbom/workloads?"+url.Values{"project": {cluster}, "kind": {"cluster"}}.Encode(), body, &res)
	return res.Workloads, err
}

// checkURL refuses to send the token (and the inventory) in clear text: https only, except to
// this machine.
func checkURL(base string) error {
	u, err := url.Parse(base)
	if err != nil {
		return fmt.Errorf("API URL %q: %w", base, err)
	}
	switch {
	case u.Scheme == "https" && u.Host != "":
		return nil
	case u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"):
		return nil
	}
	return fmt.Errorf("API URL %q: only https:// is allowed (http:// for localhost)", base)
}

func (c *Client) do(ctx context.Context, method, path string, body []byte, out any) (int, error) {
	if c.Token == "" {
		return 0, errors.New("no API token: put it in /etc/wpsbom/token (mode 600), or use --api-token-file / WPSBOM_TOKEN")
	}
	base := strings.TrimRight(c.URL, "/")
	if base == "" {
		base = DefaultURL
	}
	if err := checkURL(base); err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 2 * time.Minute}
	}
	res, err := hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if res.StatusCode >= 300 && res.StatusCode != http.StatusUnprocessableEntity {
		var e struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(b, &e)
		if e.Code != "" {
			return res.StatusCode, fmt.Errorf("%s %s: %s (%s)", method, path, res.Status, e.Code)
		}
		return res.StatusCode, fmt.Errorf("%s %s: %s", method, path, res.Status)
	}
	if out != nil && len(b) > 0 {
		if err := json.Unmarshal(b, out); err != nil {
			return res.StatusCode, fmt.Errorf("%s %s: bad response: %w", method, path, err)
		}
	}
	return res.StatusCode, nil
}

// ProjectName turns an image repository into a project name: Docker Hub's prefixes dropped
// ("index.docker.io/library/nginx" → "nginx"), at most 80 characters (the end kept).
func ProjectName(repo string) string {
	n := strings.TrimPrefix(repo, "index.docker.io/")
	n = strings.TrimPrefix(n, "docker.io/")
	n = strings.TrimPrefix(n, "library/")
	n = strings.Trim(n, " ./-")
	// Too long: cut, plus a hash of the whole name. Keeping only the end would let
	// "evil.io/aaaa…ghcr.io/acme/shop" take the name (and project) of ghcr.io/acme/shop.
	if len(n) > 80 {
		sum := sha256.Sum256([]byte(n))
		n = strings.TrimRight(n[:63], " ./-") + "-" + hex.EncodeToString(sum[:])[:16]
	}
	return n
}
