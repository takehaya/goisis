package main

import "testing"

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
		{":50051", false},          // empty host
		{"127.0.0.1", false},       // missing port: unparseable
		{"not an address", false},
	} {
		if got := nonLoopbackAPI(tc.addr); got != tc.want {
			t.Errorf("nonLoopbackAPI(%q) = %v, want %v", tc.addr, got, tc.want)
		}
	}
}
