// Package docker talks to the Docker Engine API over its unix socket, read-only: list running
// containers, inspect a container or an image, export an image ("docker save"). It needs access to the socket
// (root or the docker group) and nothing else; no Docker client library is linked in.
package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// DefaultSocket is where dockerd listens; DOCKER_HOST=unix:///… overrides it.
const DefaultSocket = "/var/run/docker.sock"

// Client is a Docker Engine API client.
type Client struct {
	http *http.Client
}

// New returns a client for DOCKER_HOST (unix sockets only) or the default socket.
func New() (*Client, error) {
	sock := DefaultSocket
	if h := os.Getenv("DOCKER_HOST"); h != "" {
		if !strings.HasPrefix(h, "unix://") {
			return nil, fmt.Errorf("DOCKER_HOST %q: only unix:// sockets are supported", h)
		}
		sock = strings.TrimPrefix(h, "unix://")
	}
	if _, err := os.Stat(sock); err != nil {
		return nil, fmt.Errorf("docker socket: %w", err)
	}
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", sock)
	}}
	return &Client{http: &http.Client{Transport: tr}}, nil
}

// ErrNotFound is returned for an image the daemon does not have.
var ErrNotFound = errors.New("no such image")

func (c *Client) get(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return nil, err
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode == http.StatusNotFound {
		res.Body.Close()
		return nil, ErrNotFound
	}
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 1024))
		res.Body.Close()
		return nil, fmt.Errorf("docker %s: %s: %s", path, res.Status, strings.TrimSpace(string(b)))
	}
	return res, nil
}

func (c *Client) getJSON(ctx context.Context, path string, v any) error {
	res, err := c.get(ctx, path)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	return json.NewDecoder(res.Body).Decode(v)
}

// Container is a running container as /containers/json lists it.
type Container struct {
	ID      string   `json:"Id"`
	Names   []string `json:"Names"`
	Image   string   `json:"Image"`
	ImageID string   `json:"ImageID"`
}

// Name is the container's name without the leading "/".
func (c Container) Name() string {
	if len(c.Names) == 0 {
		return ""
	}
	return strings.TrimPrefix(c.Names[0], "/")
}

// Containers lists the running containers.
func (c *Client) Containers(ctx context.Context) ([]Container, error) {
	var out []Container
	err := c.getJSON(ctx, "/containers/json", &out)
	return out, err
}

// Mount is a volume or bind mount of a container.
type Mount struct {
	Type        string `json:"Type"` // bind, volume, tmpfs
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
}

// ContainerInspect is the part of /containers/{id}/json wpsbom uses.
type ContainerInspect struct {
	ID    string `json:"Id"`
	Name  string `json:"Name"`
	Image string `json:"Image"` // image ID
	State struct {
		Pid int `json:"Pid"`
	} `json:"State"`
	Config struct {
		Image      string `json:"Image"`
		WorkingDir string `json:"WorkingDir"`
	} `json:"Config"`
	// GraphDriver.Data.MergedDir is the container's root file system on the host (overlay2).
	GraphDriver struct {
		Name string            `json:"Name"`
		Data map[string]string `json:"Data"`
	} `json:"GraphDriver"`
	Mounts []Mount `json:"Mounts"`
}

// InspectContainer looks a container up by ID or name.
func (c *Client) InspectContainer(ctx context.Context, id string) (*ContainerInspect, error) {
	var out ContainerInspect
	if err := c.getJSON(ctx, "/containers/"+url.PathEscape(id)+"/json", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ImageInspect is the part of /images/{name}/json wpsbom uses.
type ImageInspect struct {
	ID          string   `json:"Id"`
	RepoTags    []string `json:"RepoTags"`
	RepoDigests []string `json:"RepoDigests"`
	Os          string   `json:"Os"`
	Arch        string   `json:"Architecture"`
}

// Inspect looks an image up by reference or ID.
func (c *Client) Inspect(ctx context.Context, ref string) (*ImageInspect, error) {
	var out ImageInspect
	if err := c.getJSON(ctx, "/images/"+url.PathEscape(ref)+"/json", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Save writes the image as a "docker save" tar archive to w.
func (c *Client) Save(ctx context.Context, ref string, w io.Writer) error {
	res, err := c.get(ctx, "/images/get?names="+url.QueryEscape(ref))
	if err != nil {
		return err
	}
	defer res.Body.Close()
	_, err = io.Copy(w, res.Body)
	return err
}
