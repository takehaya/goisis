package main

import (
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestParseAPIListen(t *testing.T) {
	for _, tc := range []struct {
		addr        string
		wantNetwork string
		wantAddress string
		ok          bool
	}{
		{"127.0.0.1:50051", "tcp", "127.0.0.1:50051", true},
		{":50051", "tcp", ":50051", true},
		{"unix:///tmp/x.sock", "unix", "/tmp/x.sock", true},
		{"unix://relative", "", "", false},
		{"unix://", "", "", false},
	} {
		network, address, err := parseAPIListen(tc.addr)
		if (err == nil) != tc.ok {
			t.Errorf("parseAPIListen(%q) ok=%v, want %v (err=%v)", tc.addr, err == nil, tc.ok, err)
			continue
		}
		if network != tc.wantNetwork || address != tc.wantAddress {
			t.Errorf("parseAPIListen(%q) = %q, %q, want %q, %q", tc.addr, network, address, tc.wantNetwork, tc.wantAddress)
		}
	}
}

func TestListenAPIUnixSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "goisisd.sock")

	ln, err := listenAPI("unix://" + path)
	if err != nil {
		t.Fatalf("listenAPI: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
	srv := &http.Server{Handler: mux} //nolint:gosec // no timeouts needed for a test server
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o660 {
		t.Errorf("socket mode = %o, want 660", got)
	}

	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := io.WriteString(conn, "GET /healthz HTTP/1.0\r\n\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	res, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.HasSuffix(string(res), "ok") {
		t.Errorf("response = %q, want it to end in %q", res, "ok")
	}
}

func TestListenAPIReplacesStaleSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "goisisd.sock")

	ln, err := listenAPI("unix://" + path)
	if err != nil {
		t.Fatalf("listenAPI: %v", err)
	}
	// Leave the file behind, as an unclean exit would.
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	ln, err = listenAPI("unix://" + path)
	if err != nil {
		t.Fatalf("listenAPI over a stale socket: %v", err)
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// TestListenAPIUnixSocketIsGroupOnlyUnderAPermissiveUmask asserts the socket is
// never created wider than 0660, whatever umask the daemon inherited, and that
// listenAPI leaves the process umask as it found it.
func TestListenAPIUnixSocketIsGroupOnlyUnderAPermissiveUmask(t *testing.T) {
	prev := syscall.Umask(0)
	t.Cleanup(func() { syscall.Umask(prev) })

	path := filepath.Join(t.TempDir(), "goisisd.sock")
	ln, err := listenAPI("unix://" + path)
	if err != nil {
		t.Fatalf("listenAPI: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat socket: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o660 {
		t.Errorf("socket mode = %o, want 660", got)
	}
	if got := syscall.Umask(0); got != 0 {
		syscall.Umask(got)
		t.Errorf("umask after listenAPI = %o, want it restored to 0", got)
	}
}

// TestListenAPIRefusesASymlinkInPlaceOfTheSocket asserts the stale-socket check
// looks at the path itself, so a symlink planted where the socket belongs is
// refused rather than followed.
func TestListenAPIRefusesASymlinkInPlaceOfTheSocket(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.sock")
	ln, err := net.Listen("unix", target)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	path := filepath.Join(dir, "goisisd.sock")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}

	if _, err := listenAPI("unix://" + path); err == nil {
		t.Fatal("listenAPI over a symlink succeeded, want refusal")
	}
	if _, err := os.Lstat(path); err != nil {
		t.Errorf("the symlink was removed: %v", err)
	}
}

func TestListenAPIRefusesNonSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-socket")
	if err := os.WriteFile(path, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := listenAPI("unix://" + path); err == nil {
		t.Fatal("listenAPI on a regular file succeeded, want refusal")
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("the regular file was removed: %v", err)
	}
}

func TestNonLoopbackAPI(t *testing.T) {
	for _, tc := range []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:50051", false},
		{"127.0.0.2:50051", false}, // any 127/8 address is loopback
		{"[::1]:50051", false},
		{"0.0.0.0:50051", true},
		{"[::]:50051", true},
		{"192.0.2.1:50051", true},
		{"[2001:db8::1]:50051", true},
		{"localhost:50051", false}, // hostnames are left to the operator
		{":50051", true},           // an empty host binds every interface
		{"127.0.0.1", false},       // missing port: unparseable
		{"not an address", false},
		{"unix:///tmp/x.sock", false}, // a unix socket is local by construction
	} {
		if got := nonLoopbackAPI(tc.addr); got != tc.want {
			t.Errorf("nonLoopbackAPI(%q) = %v, want %v", tc.addr, got, tc.want)
		}
	}
}
