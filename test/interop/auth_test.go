package interop

import (
	"context"
	"testing"
)

// TestHelloAuthInterop verifies HMAC-MD5 hello authentication (RFC 5304) is
// wire-compatible with FRR: with a matching `isis password md5`, the adjacency
// forms, which means each side accepted the other's digest. A mismatch would
// prevent it (covered in-process by pkg/server).
func TestHelloAuthInterop(t *testing.T) {
	requireInterop(t)
	const pw = "s3cretpw"

	node := startFRR(t, true, " isis password md5 "+pw)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := startGoisis(t, ctx, node.hostVeth, true, pw)

	waitUp(t, "goisis<->FRR adjacency up with matching HMAC-MD5 hello auth", func() bool {
		return goisisSeesUp(t, s, frrSysID) && node.neighborUp(t, "goisis")
	})
}
