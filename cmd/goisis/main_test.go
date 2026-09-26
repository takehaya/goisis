package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/spf13/cobra"

	goisisv1 "github.com/takehaya/goisis/gen/goisis/v1"
	"github.com/takehaya/goisis/gen/goisis/v1/goisisv1connect"
	"github.com/takehaya/goisis/internal/version"
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

// TestRestartStr: the neighbour table's RFC 5306 column. Both conditions
// leave the adjacency reading Up, so an operator scanning the table has only
// this column to tell a neighbour restarting gracefully from one that is
// broken -- and the healthy answer has to be the quiet one.
func TestRestartStr(t *testing.T) {
	for _, tc := range []struct {
		a    *goisisv1.Adjacency
		want string
	}{
		{&goisisv1.Adjacency{}, "-"},
		{&goisisv1.Adjacency{Restarting: true}, "restarting"},
		{&goisisv1.Adjacency{Suppressed: true}, "suppressed"},
		{&goisisv1.Adjacency{Restarting: true, Suppressed: true}, "restarting,suppressed"},
	} {
		if got := restartStr(tc.a); got != tc.want {
			t.Errorf("restartStr(%+v) = %q, want %q", tc.a, got, tc.want)
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

// stubService answers the two RPCs behind the commands that render without
// printResponse. Everything else is left unimplemented: the assertion is which
// stream the rendering lands on, not what the daemon would have said.
type stubService struct {
	goisisv1connect.UnimplementedIsisServiceHandler
}

func (stubService) GetIsis(context.Context, *connect.Request[goisisv1.GetIsisRequest]) (*connect.Response[goisisv1.GetIsisResponse], error) {
	return connect.NewResponse(&goisisv1.GetIsisResponse{Global: &goisisv1.Global{
		Version: "test", SystemId: "0000.0000.0001", Overload: true,
	}}), nil
}

func (stubService) ListAdjacencies(context.Context, *connect.Request[goisisv1.ListAdjacenciesRequest]) (*connect.Response[goisisv1.ListAdjacenciesResponse], error) {
	return connect.NewResponse(&goisisv1.ListAdjacenciesResponse{Adjacencies: []*goisisv1.Adjacency{{
		SystemId: "0000.0000.0002", Interface: "eth0", Level: goisisv1.Level_LEVEL_2,
		State: "Up", Snpa: "0000.0000.00b2", HoldingTime: 30, HoldingRemaining: 7, Restarting: true,
	}}}), nil
}

// WatchEvent sends the three events a neighbour's restart produces on the
// server side: entering restart, entering suppression, and leaving both. All
// three carry State "Up", because an adjacency the helper holds never leaves
// it -- which is the reason the stream reports the conditions at all.
func (stubService) WatchEvent(_ context.Context, _ *connect.Request[goisisv1.WatchEventRequest], stream *connect.ServerStream[goisisv1.WatchEventResponse]) error {
	for _, adj := range []*goisisv1.Adjacency{
		{SystemId: "0000.0000.0002", Interface: "eth0", Level: goisisv1.Level_LEVEL_2, State: "Up", Restarting: true},
		{SystemId: "0000.0000.0002", Interface: "eth0", Level: goisisv1.Level_LEVEL_2, State: "Up", Restarting: true, Suppressed: true},
		{SystemId: "0000.0000.0002", Interface: "eth0", Level: goisisv1.Level_LEVEL_2, State: "Up"},
	} {
		if err := stream.Send(&goisisv1.WatchEventResponse{Event: &goisisv1.WatchEventResponse_Adjacency{
			Adjacency: &goisisv1.AdjacencyEvent{Adjacency: adj},
		}}); err != nil {
			return err
		}
	}
	return nil
}

// TestCommandsWriteTheirAnswerToStdout covers the renderers that do not go
// through printResponse. Each writes with cobra's Print helpers in a form that
// looks right and lands on stderr, so the assertion is the stream: the out
// writer is left unset, which is what the real binary does, and os.Stdout is
// captured around the run.
func TestCommandsWriteTheirAnswerToStdout(t *testing.T) {
	_, handler := goisisv1connect.NewIsisServiceHandler(stubService{})
	mux := http.NewServeMux()
	mux.Handle(goisisv1connect.IsisServiceGetIsisProcedure, handler)
	mux.Handle(goisisv1connect.IsisServiceWatchEventProcedure, handler)
	mux.Handle(goisisv1connect.IsisServiceListAdjacenciesProcedure, handler)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		// What a script does: V=$(goisis version). It was empty.
		{"version", []string{"version"}, version.Version},
		{"global", []string{"global", "--addr", srv.URL}, "system-id: 0000.0000.0001"},
		{"monitor", []string{"monitor", "--addr", srv.URL}, "ADJ  0000.0000.0002 eth0 L2 Up"},
		// The three lines the three events above have to become. State is
		// "Up" on all three, so without the last column an operator watching
		// a neighbour's maintenance window sees one line repeated -- churn,
		// where the feature exists to report a restart that by definition
		// moves no state.
		{"monitor renders entering restart", []string{"monitor", "--addr", srv.URL}, "ADJ  0000.0000.0002 eth0 L2 Up restarting\n"},
		{"monitor renders entering suppression", []string{"monitor", "--addr", srv.URL}, "ADJ  0000.0000.0002 eth0 L2 Up restarting,suppressed\n"},
		{"monitor renders leaving both", []string{"monitor", "--addr", srv.URL}, "ADJ  0000.0000.0002 eth0 L2 Up -\n"},
		{"global as json", []string{"global", "--addr", srv.URL, "-o", "json"}, `"systemId"`},
		{"neighbor renders the restart column", []string{"neighbor", "--addr", srv.URL}, "restarting"},
		// The hold that is left is a column of its own, so it is visible next
		// to the advertised one rather than only in -o json.
		{"neighbor renders the hold left beside the one advertised", []string{"neighbor", "--addr", srv.URL}, "30    7       restarting"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var errBuf bytes.Buffer
			root := newRootCmd()
			root.SetErr(&errBuf)
			root.SetArgs(tc.args)
			stdout := captureStdout(t, func() {
				if err := root.Execute(); err != nil {
					t.Errorf("%v: %v", tc.args, err)
				}
			})
			if !strings.Contains(stdout, tc.want) {
				t.Errorf("stdout = %q, want it to contain %q", stdout, tc.want)
			}
			if errBuf.Len() != 0 {
				t.Errorf("stderr = %q, want nothing there", errBuf.String())
			}
		})
	}
}

// TestMonitorHonorsTheOutputFormat guarantees that the persistent -o flag
// means something on the one command that streams. A stream has no single
// response message to marshal, so "json" is one JSON value per event -- the
// same shape every other command emits, read back by the same jq pipeline --
// and a format neither renderer knows is an error before the stream blocks,
// rather than a flag accepted and ignored.
func TestMonitorHonorsTheOutputFormat(t *testing.T) {
	_, handler := goisisv1connect.NewIsisServiceHandler(stubService{})
	mux := http.NewServeMux()
	mux.Handle(goisisv1connect.IsisServiceWatchEventProcedure, handler)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	t.Run("json is one value per event", func(t *testing.T) {
		var out, errBuf bytes.Buffer
		root := newRootCmd()
		root.SetOut(&out)
		root.SetErr(&errBuf)
		root.SetArgs([]string{"monitor", "--addr", srv.URL, "-o", "json"})
		if err := root.Execute(); err != nil {
			t.Fatalf("monitor -o json: %v", err)
		}
		dec := json.NewDecoder(strings.NewReader(out.String()))
		var restarting []bool
		for dec.More() {
			var ev struct {
				Adjacency struct {
					Adjacency struct {
						Restarting bool `json:"restarting"`
					} `json:"adjacency"`
				} `json:"adjacency"`
			}
			if err := dec.Decode(&ev); err != nil {
				t.Fatalf("output is not a stream of JSON values: %v\n%s", err, out.String())
			}
			restarting = append(restarting, ev.Adjacency.Adjacency.Restarting)
		}
		if want := []bool{true, true, false}; len(restarting) != len(want) {
			t.Fatalf("decoded %d events %v, want %d (%v)", len(restarting), restarting, len(want), want)
		} else {
			for i := range want {
				if restarting[i] != want[i] {
					t.Errorf("event %d restarting = %t, want %t", i, restarting[i], want[i])
				}
			}
		}
	})

	t.Run("an unknown format is refused, not ignored", func(t *testing.T) {
		var out, errBuf bytes.Buffer
		root := newRootCmd()
		root.SetOut(&out)
		root.SetErr(&errBuf)
		root.SetArgs([]string{"monitor", "--addr", srv.URL, "-o", "yaml"})
		if err := root.Execute(); err == nil {
			t.Errorf("monitor -o yaml was accepted and printed %q, want an error", out.String())
		}
	})
}
