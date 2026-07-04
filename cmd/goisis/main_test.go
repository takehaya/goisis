package main

import (
	"testing"

	goisisv1 "github.com/takehaya/goisis/gen/goisis/v1"
	"github.com/takehaya/goisis/pkg/packet"
)

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
