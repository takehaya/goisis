package interop

import (
	"context"
	"testing"

	"github.com/takehaya/goisis/pkg/server"
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

// TestLSPAuthInterop verifies HMAC-MD5 LSP/SNP authentication (RFC 5304,
// area/domain password) is wire-compatible with FRR: with matching keys the
// LSDB syncs both ways (each side accepts the other's authenticated LSPs).
func TestLSPAuthInterop(t *testing.T) {
	requireInterop(t)
	const pw = "lsp5304pw"

	node := startFRR(t, true, "", " area-password md5 "+pw+"\n domain-password md5 "+pw)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := startGoisis(t, ctx, node.hostVeth, true, "",
		server.WithAreaPassword(pw), server.WithDomainPassword(pw))

	waitUp(t, "adjacency up", func() bool {
		return goisisSeesUp(t, s, frrSysID) && node.neighborUp(t, "goisis")
	})
	// goisis must accept FRR's authenticated LSP, and FRR must accept goisis's.
	waitUp(t, "goisis has FRR's authenticated LSP", func() bool { return goisisHasLSPFrom(t, s, frrSysID) })
	waitUp(t, "FRR has goisis's authenticated LSP", func() bool { return node.databaseContains(t, "goisis") })
}
