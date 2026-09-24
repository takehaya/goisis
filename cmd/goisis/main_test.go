package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	goisisv1 "github.com/takehaya/goisis/gen/goisis/v1"
	"github.com/takehaya/goisis/pkg/packet"
)

func TestNewHTTPClientTCPIsUnchanged(t *testing.T) {
	client, baseURL, err := newHTTPClient("http://127.0.0.1:50051")
	if err != nil {
		t.Fatalf("newHTTPClient: %v", err)
	}
	if client != http.DefaultClient {
		t.Error("an http:// address should keep using http.DefaultClient")
	}
	if baseURL != "http://127.0.0.1:50051" {
		t.Errorf("baseURL = %q, want the address unchanged", baseURL)
	}
}

func TestNewHTTPClientDialsUnixSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "goisisd.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "from the socket")
	})
	srv := &http.Server{Handler: mux} //nolint:gosec // no timeouts needed for a test server
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	client, baseURL, err := newHTTPClient("unix://" + path)
	if err != nil {
		t.Fatalf("newHTTPClient: %v", err)
	}
	if baseURL != "http://unix" {
		t.Errorf("baseURL = %q, want %q", baseURL, "http://unix")
	}

	res, err := client.Get(baseURL + "/hello")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "from the socket" {
		t.Errorf("body = %q, want %q", body, "from the socket")
	}
}

func TestNewHTTPClientRejectsRelativeUnixPath(t *testing.T) {
	if _, _, err := newHTTPClient("unix://goisisd.sock"); err == nil {
		t.Fatal("a relative unix path was accepted, want an error")
	}
}

func TestParseUint8(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want uint8
		ok   bool
	}{
		{"0", 0, true},
		{"128", 128, true},
		{"255", 255, true},
		{"256", 0, false},
		{"-1", 0, false},
		{"abc", 0, false},
		{"", 0, false},
	} {
		got, err := parseUint8(tc.in)
		if (err == nil) != tc.ok {
			t.Errorf("parseUint8(%q) ok=%v, want %v (err=%v)", tc.in, err == nil, tc.ok, err)
		}
		if tc.ok && got != tc.want {
			t.Errorf("parseUint8(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestParseMetricType(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want uint8
		ok   bool
	}{
		{"", packet.FlexAlgoMetricIGP, true},
		{"igp", packet.FlexAlgoMetricIGP, true},
		{"delay", packet.FlexAlgoMetricMinDelay, true},
		{"te", packet.FlexAlgoMetricTE, true},
		{"bogus", 0, false},
		{"IGP", 0, false}, // case-sensitive by design
	} {
		got, err := parseMetricType(tc.in)
		if (err == nil) != tc.ok {
			t.Errorf("parseMetricType(%q) ok=%v, want %v (err=%v)", tc.in, err == nil, tc.ok, err)
		}
		if tc.ok && got != tc.want {
			t.Errorf("parseMetricType(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestMetricTypeStr(t *testing.T) {
	for _, tc := range []struct {
		in   uint32
		want string
	}{
		{uint32(packet.FlexAlgoMetricIGP), "igp"},
		{uint32(packet.FlexAlgoMetricMinDelay), "delay"},
		{uint32(packet.FlexAlgoMetricTE), "te"},
		{7, "7"},
	} {
		if got := metricTypeStr(tc.in); got != tc.want {
			t.Errorf("metricTypeStr(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestLevelStr(t *testing.T) {
	for _, tc := range []struct {
		in   goisisv1.Level
		want string
	}{
		{goisisv1.Level_LEVEL_1, "L1"},
		{goisisv1.Level_LEVEL_2, "L2"},
		{goisisv1.Level_LEVEL_UNSPECIFIED, "-"},
	} {
		if got := levelStr(tc.in); got != tc.want {
			t.Errorf("levelStr(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestPrefStr: the route table prints the RFC 5302 §3.2 class as its number,
// lower being the more preferred, and prints a daemon that sends no class at
// all as "-" rather than as a class better than 1.
func TestPrefStr(t *testing.T) {
	for _, tc := range []struct {
		in   uint32
		want string
	}{
		{1, "1"},
		{2, "2"},
		{3, "3"},
		{0, "-"},
	} {
		if got := prefStr(tc.in); got != tc.want {
			t.Errorf("prefStr(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCircuitTypeAndLevels(t *testing.T) {
	for _, tc := range []struct {
		c          *goisisv1.Circuit
		wantType   string
		wantLevels string
	}{
		{&goisisv1.Circuit{PointToPoint: true, Level2: true}, "p2p", "L2"},
		{&goisisv1.Circuit{Level1: true, Level2: true}, "lan", "L1L2"},
		{&goisisv1.Circuit{Level1: true}, "lan", "L1"},
		{&goisisv1.Circuit{Level2: true}, "lan", "L2"},
	} {
		if got := circuitType(tc.c); got != tc.wantType {
			t.Errorf("circuitType(%+v) = %q, want %q", tc.c, got, tc.wantType)
		}
		if got := circuitLevels(tc.c); got != tc.wantLevels {
			t.Errorf("circuitLevels(%+v) = %q, want %q", tc.c, got, tc.wantLevels)
		}
	}
}

func TestNextHops(t *testing.T) {
	for _, tc := range []struct {
		r    *goisisv1.Route
		want string
	}{
		{&goisisv1.Route{}, ""},
		{&goisisv1.Route{NextHops: []*goisisv1.NextHop{
			{Gateway: "10.0.0.2", Interface: "eth0"},
		}}, "10.0.0.2 (eth0)"},
		{&goisisv1.Route{NextHops: []*goisisv1.NextHop{
			{Gateway: "10.0.0.2", Interface: "eth0"},
			{Gateway: "fe80::1", Interface: "eth1"},
		}}, "10.0.0.2 (eth0), fe80::1 (eth1)"},
	} {
		if got := nextHops(tc.r); got != tc.want {
			t.Errorf("nextHops(%+v) = %q, want %q", tc.r, got, tc.want)
		}
	}
}

func TestParseOnOff(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
		ok   bool
	}{
		{"on", true, true},
		{"off", false, true},
		{"true", false, false},
		{"ON", false, false}, // case-sensitive by design
		{"", false, false},
	} {
		got, err := parseOnOff(tc.in)
		if (err == nil) != tc.ok {
			t.Errorf("parseOnOff(%q) ok=%v, want %v (err=%v)", tc.in, err == nil, tc.ok, err)
		}
		if tc.ok && got != tc.want {
			t.Errorf("parseOnOff(%q) = %t, want %t", tc.in, got, tc.want)
		}
	}
}

// TestPrintResponseOutputFlag: the root's persistent -o reaches a subcommand,
// where "json" marshals the response message and anything but "table" is
// rejected rather than silently falling back.
func TestPrintResponseOutputFlag(t *testing.T) {
	msg := &goisisv1.GetLsdbResponse{Lsps: []*goisisv1.Lsp{{
		LspId:    "0000.0000.0001.00-00",
		Hostname: "r1",
		Tlvs:     []string{"Dynamic Hostname: r1"},
	}}}

	// Two buffers, not one: the point of the JSON format is that it can be
	// piped, so which stream it lands on is the assertion. Sharing a buffer
	// hid that it was going to stderr.
	run := func(t *testing.T, args ...string) (stdout, stderr string, err error) {
		t.Helper()
		var out, errBuf bytes.Buffer
		root := newRootCmd()
		root.SetOut(&out)
		root.SetErr(&errBuf)
		root.AddCommand(&cobra.Command{
			Use: "probe",
			RunE: func(cmd *cobra.Command, _ []string) error {
				return printResponse(cmd, msg, func() error {
					cmd.Println("TABLE")
					return nil
				})
			},
		})
		root.SetArgs(args)
		err = root.Execute()
		return out.String(), errBuf.String(), err
	}

	t.Run("json", func(t *testing.T) {
		out, _, err := run(t, "probe", "-o", "json")
		if err != nil {
			t.Fatalf("probe -o json: %v", err)
		}
		var got struct {
			Lsps []struct {
				Hostname string   `json:"hostname"`
				Tlvs     []string `json:"tlvs"`
			} `json:"lsps"`
		}
		if err := json.Unmarshal([]byte(out), &got); err != nil {
			t.Fatalf("output is not valid JSON: %v\n%s", err, out)
		}
		if len(got.Lsps) != 1 || got.Lsps[0].Hostname != "r1" {
			t.Errorf("lsps = %+v, want one LSP with hostname r1", got.Lsps)
		}
		if len(got.Lsps[0].Tlvs) != 1 {
			t.Errorf("tlvs = %q, want the rendered TLV line", got.Lsps[0].Tlvs)
		}
	})

	t.Run("table by default", func(t *testing.T) {
		out, _, err := run(t, "probe")
		if err != nil {
			t.Fatalf("probe: %v", err)
		}
		if out != "TABLE\n" {
			t.Errorf("output = %q, want the table renderer's output", out)
		}
	})

	// The stream, not the bytes. cobra's Print writes to OutOrStderr, and a
	// command whose out writer is unset -- which is every invocation of the
	// real binary -- gets os.Stderr from it. So the one format that exists to
	// be piped into jq was going to the one stream a pipe does not carry, and
	// a test that points both writers at one buffer cannot see it. Leaving the
	// out writer unset is what reproduces the binary.
	t.Run("json goes to stdout, which is what a pipe carries", func(t *testing.T) {
		var errBuf bytes.Buffer
		root := newRootCmd()
		root.SetErr(&errBuf)
		root.AddCommand(&cobra.Command{
			Use: "probe",
			RunE: func(cmd *cobra.Command, _ []string) error {
				return printResponse(cmd, msg, func() error { return nil })
			},
		})
		root.SetArgs([]string{"probe", "-o", "json"})
		stdout := captureStdout(t, func() {
			if err := root.Execute(); err != nil {
				t.Fatalf("probe -o json: %v", err)
			}
		})
		if errBuf.Len() != 0 {
			t.Errorf("stderr = %q, want nothing there", errBuf.String())
		}
		if !strings.Contains(stdout, `"hostname"`) {
			t.Errorf("stdout = %q, want the JSON response", stdout)
		}
	})

	t.Run("unknown format", func(t *testing.T) {
		if _, _, err := run(t, "probe", "-o", "yaml"); err == nil {
			t.Error("-o yaml was accepted, want an error")
		}
	})
}

// captureStdout runs fn with os.Stdout replaced by a pipe and returns what was
// written to it. The JSON output format's whole point is the stream it lands
// on, and cobra only falls back to os.Stdout when no out writer is set.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()
	fn()
	os.Stdout = orig
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return out
}
