// Package k8s lists what a Kubernetes cluster runs: every workload's containers and the image
// digest each one actually runs. It reads pods only (RBAC: get/list pods), through the API
// server's REST interface; no client library is linked in.
package k8s

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ice-s/wpsbom/pkg/push"
)

// In-cluster service account files.
const (
	saDir       = "/var/run/secrets/kubernetes.io/serviceaccount"
	saToken     = saDir + "/token"
	saCA        = saDir + "/ca.crt"
	saNamespace = saDir + "/namespace"
)

// Config says how to reach the API server. Zero values mean in-cluster.
type Config struct {
	Server    string // https://host:port
	TokenFile string
	CAFile    string
	Insecure  bool // skip TLS verification (testing only)
	// Namespace limits the listing; empty means all namespaces.
	Namespace string
}

// Client is a minimal read-only API client.
type Client struct {
	server string
	token  string
	http   *http.Client
}

// New builds a client from cfg, falling back to the pod's service account.
func New(cfg Config) (*Client, error) {
	server := cfg.Server
	if server == "" {
		host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
		if host == "" {
			return nil, errors.New("not running in a cluster: pass --server and --token-file")
		}
		server = "https://" + net.JoinHostPort(host, port)
	}
	tokenFile := cfg.TokenFile
	if tokenFile == "" {
		tokenFile = saToken
	}
	tok, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, fmt.Errorf("service account token: %w", err)
	}
	tlsCfg := &tls.Config{InsecureSkipVerify: cfg.Insecure} //nolint:gosec // opt-in, for test clusters
	caFile := cfg.CAFile
	if caFile == "" && cfg.Server == "" {
		caFile = saCA
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("cluster CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("cluster CA: no certificate found")
		}
		tlsCfg.RootCAs = pool
	}
	return &Client{
		server: strings.TrimRight(server, "/"),
		token:  strings.TrimSpace(string(tok)),
		http:   &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}},
	}, nil
}

// CurrentNamespace is the pod's own namespace, when running in a cluster.
func CurrentNamespace() string {
	b, _ := os.ReadFile(saNamespace)
	return strings.TrimSpace(string(b))
}

type ownerRef struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

type pod struct {
	Metadata struct {
		Name            string            `json:"name"`
		Namespace       string            `json:"namespace"`
		Labels          map[string]string `json:"labels"`
		OwnerReferences []ownerRef        `json:"ownerReferences"`
	} `json:"metadata"`
	Status struct {
		Phase             string `json:"phase"`
		ContainerStatuses []struct {
			Name    string `json:"name"`
			Image   string `json:"image"`
			ImageID string `json:"imageID"`
		} `json:"containerStatuses"`
		InitContainerStatuses []struct{} `json:"initContainerStatuses"`
	} `json:"status"`
}

type podList struct {
	Items    []pod `json:"items"`
	Metadata struct {
		Continue string `json:"continue"`
	} `json:"metadata"`
}

// Workloads lists running pods and groups their containers by workload and image digest.
func (c *Client) Workloads(ctx context.Context, namespace string) ([]push.Workload, error) {
	path := "/api/v1/pods"
	if namespace != "" {
		path = "/api/v1/namespaces/" + url.PathEscape(namespace) + "/pods"
	}
	type key struct{ ns, kind, name, container, digest string }
	agg := map[key]*push.Workload{}
	cont := ""
	for {
		q := url.Values{"limit": {"500"}, "fieldSelector": {"status.phase=Running"}}
		if cont != "" {
			q.Set("continue", cont)
		}
		var list podList
		if err := c.get(ctx, path+"?"+q.Encode(), &list); err != nil {
			return nil, err
		}
		for _, p := range list.Items {
			kind, name := Owner(p.Metadata.Name, p.Metadata.Labels, p.Metadata.OwnerReferences)
			for _, cs := range p.Status.ContainerStatuses {
				repo, digest := ParseImageID(cs.ImageID, cs.Image)
				if digest == "" {
					continue
				}
				k := key{p.Metadata.Namespace, kind, name, cs.Name, digest}
				w := agg[k]
				if w == nil {
					w = &push.Workload{Namespace: k.ns, Kind: kind, Name: name, Container: cs.Name, Image: cs.Image, Repo: repo, Digest: digest}
					agg[k] = w
				}
				w.Replicas++
			}
		}
		if cont = list.Metadata.Continue; cont == "" {
			break
		}
	}
	out := make([]push.Workload, 0, len(agg))
	for _, w := range agg {
		out = append(out, *w)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		return a.Namespace+"/"+a.Kind+"/"+a.Name+"/"+a.Container < b.Namespace+"/"+b.Kind+"/"+b.Name+"/"+b.Container
	})
	return out, nil
}

func (c *Client) get(ctx context.Context, path string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.server+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 512))
		return fmt.Errorf("kubernetes %s: %s: %s", path, res.Status, strings.TrimSpace(string(b)))
	}
	return json.NewDecoder(res.Body).Decode(v)
}

var (
	rsHash      = regexp.MustCompile(`-[a-z0-9]{6,10}$`)
	jobSchedule = regexp.MustCompile(`-\d{8,}$`)
)

// Owner names the workload a pod belongs to, without extra API calls: a ReplicaSet's name is
// its Deployment's plus the pod-template-hash, a CronJob's Job its own plus a schedule time.
func Owner(podName string, labels map[string]string, refs []ownerRef) (kind, name string) {
	if len(refs) == 0 {
		return "Pod", podName
	}
	o := refs[0]
	switch o.Kind {
	case "ReplicaSet":
		if h := labels["pod-template-hash"]; h != "" && strings.HasSuffix(o.Name, "-"+h) {
			return "Deployment", strings.TrimSuffix(o.Name, "-"+h)
		}
		if rsHash.MatchString(o.Name) {
			return "Deployment", rsHash.ReplaceAllString(o.Name, "")
		}
		return "ReplicaSet", o.Name
	case "Job":
		if jobSchedule.MatchString(o.Name) {
			return "CronJob", jobSchedule.ReplaceAllString(o.Name, "")
		}
	}
	return o.Kind, o.Name
}

// ParseImageID reads the repository and digest out of a container status imageID, in its runtime
// spellings: "docker-pullable://repo@sha256:…", "repo@sha256:…", or a bare "sha256:…" (then the
// repository comes from the image field).
func ParseImageID(imageID, image string) (repo, digest string) {
	id := imageID
	if i := strings.Index(id, "://"); i >= 0 {
		id = id[i+3:]
	}
	if r, d, ok := strings.Cut(id, "@"); ok {
		return r, d
	}
	if strings.HasPrefix(id, "sha256:") {
		repo = image
		if i := strings.Index(repo, "@"); i >= 0 {
			repo = repo[:i]
		} else if i := strings.LastIndex(repo, ":"); i > strings.LastIndex(repo, "/") {
			repo = repo[:i]
		}
		return repo, id
	}
	return "", ""
}
