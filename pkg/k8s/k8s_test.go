package k8s

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestOwner(t *testing.T) {
	cases := []struct {
		pod    string
		labels map[string]string
		refs   []ownerRef
		kind   string
		name   string
	}{
		{"shop-7d9f8b6c5-x2k4q", map[string]string{"pod-template-hash": "7d9f8b6c5"}, []ownerRef{{"ReplicaSet", "shop-7d9f8b6c5"}}, "Deployment", "shop"},
		{"api-6f7c9-abcde", nil, []ownerRef{{"ReplicaSet", "api-6f7c9d8b4"}}, "Deployment", "api"},
		{"db-0", nil, []ownerRef{{"StatefulSet", "db"}}, "StatefulSet", "db"},
		{"backup-28123456-xyz", nil, []ownerRef{{"Job", "backup-28123456"}}, "CronJob", "backup"},
		{"migrate-abc", nil, []ownerRef{{"Job", "migrate"}}, "Job", "migrate"},
		{"debug", nil, nil, "Pod", "debug"},
	}
	for _, c := range cases {
		kind, name := Owner(c.pod, c.labels, c.refs)
		if kind != c.kind || name != c.name {
			t.Errorf("%s: got %s/%s, want %s/%s", c.pod, kind, name, c.kind, c.name)
		}
	}
}

func TestParseImageID(t *testing.T) {
	cases := []struct{ id, image, repo, digest string }{
		{"docker-pullable://ghcr.io/acme/shop@sha256:abc", "ghcr.io/acme/shop:1.2", "ghcr.io/acme/shop", "sha256:abc"},
		{"docker.io/library/nginx@sha256:def", "nginx:1.27", "docker.io/library/nginx", "sha256:def"},
		{"sha256:123", "registry:5000/app:v1", "registry:5000/app", "sha256:123"},
		{"", "nginx", "", ""},
	}
	for _, c := range cases {
		repo, digest := ParseImageID(c.id, c.image)
		if repo != c.repo || digest != c.digest {
			t.Errorf("%s: got %s %s", c.id, repo, digest)
		}
	}
}

func TestWorkloads(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" || r.URL.Path != "/api/v1/pods" {
			http.Error(w, "no", http.StatusForbidden)
			return
		}
		w.Write([]byte(`{"items":[
		 {"metadata":{"name":"shop-aaa-1","namespace":"prod","labels":{"pod-template-hash":"aaa"},"ownerReferences":[{"kind":"ReplicaSet","name":"shop-aaa"}]},
		  "status":{"containerStatuses":[{"name":"php","image":"ghcr.io/acme/shop:1","imageID":"ghcr.io/acme/shop@sha256:s1"}]}},
		 {"metadata":{"name":"shop-aaa-2","namespace":"prod","labels":{"pod-template-hash":"aaa"},"ownerReferences":[{"kind":"ReplicaSet","name":"shop-aaa"}]},
		  "status":{"containerStatuses":[{"name":"php","image":"ghcr.io/acme/shop:1","imageID":"ghcr.io/acme/shop@sha256:s1"}]}}
		],"metadata":{}}`))
	}))
	defer srv.Close()
	tok := filepath.Join(t.TempDir(), "token")
	os.WriteFile(tok, []byte("tok\n"), 0o600)
	c, err := New(Config{Server: srv.URL, TokenFile: tok})
	if err != nil {
		t.Fatal(err)
	}
	ws, err := c.Workloads(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(ws) != 1 || ws[0].Name != "shop" || ws[0].Kind != "Deployment" || ws[0].Replicas != 2 || ws[0].Digest != "sha256:s1" {
		t.Fatalf("%+v", ws)
	}
}
