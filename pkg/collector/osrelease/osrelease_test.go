package osrelease

import (
	"os"
	"slices"
	"testing"
)

func TestParse(t *testing.T) {
	cases := []struct {
		file, id, version, codename, qualifier string
		like                                   []string
	}{
		{"debian-12", "debian", "12", "bookworm", "debian-12", nil},
		{"ubuntu-24.04", "ubuntu", "24.04", "noble", "ubuntu-24.04", []string{"debian"}},
		{"alpine-3.20", "alpine", "3.20.10", "", "alpine-3.20.10", nil},
	}
	for _, c := range cases {
		b, err := os.ReadFile("testdata/" + c.file)
		if err != nil {
			t.Fatal(err)
		}
		d := Parse(b)
		if d.ID != c.id || d.VersionID != c.version || d.VersionCodename != c.codename || !slices.Equal(d.IDLike, c.like) {
			t.Errorf("%s: got %+v", c.file, d)
		}
		if q := d.Qualifier(); q != c.qualifier {
			t.Errorf("%s: qualifier %q, want %q", c.file, q, c.qualifier)
		}
	}
}

func TestQuoting(t *testing.T) {
	d := Parse([]byte("# comment\nID='rocky'\nNAME=\"Say \\\"hi\\\" \\$HOME\"\nVERSION_CODENAME=trixie\n"))
	if d.ID != "rocky" || d.Name != `Say "hi" $HOME` {
		t.Errorf("got %+v", d)
	}
	if q := d.Qualifier(); q != "rocky-trixie" {
		t.Errorf("qualifier without VERSION_ID: %q", q)
	}
}
