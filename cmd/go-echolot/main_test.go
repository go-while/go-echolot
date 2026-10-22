package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-while/go-echolot/internal/config"
)

func runCmd(args ...string) (code int, stdout, stderr string) {
	var o, e bytes.Buffer
	code = run(args, &o, &e)
	return code, o.String(), e.String()
}

func TestUsage(t *testing.T) {
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{nil, 2, "usage: go-echolot <command>"},
		{[]string{"help"}, 0, "dumpconf"},
		{[]string{"--help"}, 0, "version"},
		{[]string{"nosuch"}, 2, `unknown command "nosuch"`},
		{[]string{"version", "extra"}, 2, `unexpected argument "extra"`},
		{[]string{"dumpconf", "--nosuch"}, 2, "flag provided but not defined"},
		{[]string{"dumpconf", "-h"}, 0, "-config"},
	} {
		code, _, stderr := runCmd(tc.args...)
		if code != tc.code || !strings.Contains(stderr, tc.want) {
			t.Errorf("%q: exit %d, stderr %q; want exit %d with %q", tc.args, code, stderr, tc.code, tc.want)
		}
	}
}

func TestVersion(t *testing.T) {
	code, stdout, _ := runCmd("version")
	if code != 0 || !strings.HasPrefix(stdout, "go-echolot ") {
		t.Errorf("exit %d, %q", code, stdout)
	}
	version = "v1.2.3"
	defer func() { version = "" }()
	if _, stdout, _ := runCmd("version"); stdout != "go-echolot v1.2.3\n" {
		t.Errorf("with -X main.version: %q", stdout)
	}
}

func TestDumpconf(t *testing.T) {
	example := filepath.Join("..", "..", "examples", "config.ini")
	code, stdout, stderr := runCmd("dumpconf", "--config", example)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	// The output is a config file that loads to the same config.
	want, err := config.Load(example)
	if err != nil {
		t.Fatal(err)
	}
	got, err := config.Parse("dumpconf", []byte(stdout))
	if err != nil {
		t.Fatalf("dumpconf output doesn't load: %v\n%s", err, stdout)
	}
	var a, b bytes.Buffer
	want.Format(&a)
	got.Format(&b)
	if a.String() != b.String() {
		t.Errorf("dumpconf output differs:\n%s", stdout)
	}

	bad := filepath.Join(t.TempDir(), "bad.ini")
	if err := os.WriteFile(bad, []byte("[pinger]\nsitename = x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = runCmd("dumpconf", "--config", bad)
	if code != 1 || stdout != "" || !strings.Contains(stderr, "pinger.address is required") {
		t.Errorf("bad config: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}
