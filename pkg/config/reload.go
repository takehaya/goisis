package config

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"reflect"
	"slices"
	"time"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/server"
)

// Changes is the difference between two configurations, split into the calls
// that apply it and the keys that cannot be applied at all. The fields are
// applied in declaration order, which is the order the server's own rules
// require: a locator is withdrawn before the Flexible Algorithm it names is
// deleted, and an algorithm is added before a locator binds to it.
//
// The circuits bracket the rest. The deletions come first, of the circuits the
// file stopped naming, and the additions come last so that a circuit whose MTU
// lowers this node's LSP budget re-fragments once, after every other change has
// landed. A circuit named by both halves is one whose definition changed, and
// apply does not issue that deletion in this order at all: it belongs inside
// the addition (Changes.addCircuit), which is both where the name is freed
// immediately before the addition that takes it and the only place that knows
// whether the running circuit needs rebuilding at all. The additions are held
// in the file's own form and not in server.CircuitConfig, because building one
// opens a socket (CircuitConfig requires a non-nil transport) and Diff opens
// none.
type Changes struct {
	DeleteCircuits  []string
	DeleteLocators  []netip.Prefix
	DeleteFlexAlgos []uint8
	AddFlexAlgos    []server.FlexAlgoConfig
	AddLocators     []server.SRv6LocatorConfig
	DeletePrefixes  []netip.Prefix
	AddPrefixes     []server.AdvertisedPrefix
	AddCircuits     []CircuitConfig
	// Ignored names every difference a reload leaves unapplied, by the key it
	// is written under in the file ("net", "policy"). Values are never
	// included: half of these keys are secrets. A difference that is neither
	// applied nor named here would be a reload that quietly ran half the file,
	// which is worse than one that refuses.
	Ignored []string
	// open is how AddCircuits get their transports, carried here rather than
	// taken in Diff: Diff is documented as changing nothing, and Reload calls
	// it before deciding to apply anything, so opening there would cost a
	// socket per interface for a reload then refused on an unrelated key. It
	// is unexported so a Changes written by hand needs no value for it; nil
	// selects defaultOpenCircuit, exactly as Config.OpenCircuit does.
	open func(ifname string) (datalink.Transport, []netip.Addr, []netip.Addr, error)
}

// ErrPartiallyApplied reports that a reload issued every call in its batch and
// the server refused at least one of them. It is the outcome that distinguishes
// a reload from a restart: the node is then in neither configuration, since the
// batch has to withdraw a resource before it can re-add it and nothing puts
// back what a refused re-add would have restored. A daemon that gets this has
// to say so — the node is not in the state the file describes, and only another
// SIGHUP, once whatever was refused is no longer refused, will make it so. That
// retry re-issues the whole batch: the calls that already landed are satisfied
// rather than refused (see apply), so a corrected file is adopted on the next
// signal rather than latching on its own leftovers.
var ErrPartiallyApplied = errors.New("the node is not in the state the configuration file describes")

// restartOnly names every configuration key no runtime API expresses, paired
// with the value a reload compares. It is a table rather than a chain of ifs
// because that is what lets a test check it against the fields of Config: a
// key added later and forgotten here would be reported by nothing.
var restartOnly = []struct {
	key string
	of  func(*Config) any
}{
	{"net", func(c *Config) any { return c.NET }},
	{"hostname", func(c *Config) any { return c.Hostname }},
	{"fib", func(c *Config) any { return c.FIB }},
	{"fib-table", func(c *Config) any { return c.FIBTable }},
	{"overload-on-startup", func(c *Config) any { return c.OverloadOnStartup }},
	{"lsp-mtu", func(c *Config) any { return c.LSPMTU }},
	{"lsdb-entry-limit", func(c *Config) any { return c.LSDBEntryLimit }},
	{"area-password", func(c *Config) any { return c.AreaPassword }},
	{"area-accept-passwords", func(c *Config) any { return c.AreaAcceptPasswords }},
	{"area-auth-algorithm", func(c *Config) any { return c.AreaAuthAlgorithm }},
	{"area-key-id", func(c *Config) any { return c.AreaKeyID }},
	{"domain-password", func(c *Config) any { return c.DomainPassword }},
	{"domain-accept-passwords", func(c *Config) any { return c.DomainAcceptPasswords }},
	{"domain-auth-algorithm", func(c *Config) any { return c.DomainAuthAlgorithm }},
	{"domain-key-id", func(c *Config) any { return c.DomainKeyID }},
	{"policy", func(c *Config) any { return c.Policy }},
}

// Diff computes what takes a daemon running old to the configuration in next.
// It changes nothing: it parses, validates and compares, so a reload can be
// reasoned about without a server.
//
// An error means next is unusable and nothing should be applied from it. The
// first thing it does is run the validation a restart runs, because a reload
// has no rollback: a defect startup would have caught must not be found out
// half way through the batch, with the withdrawals already issued. That is
// every check that needs no transport, Options having been given the server's
// own (server.ValidateOptions): the Flex-Algo range and duplicates, a
// locator's address family and the algorithm it binds to, what a prefix may
// be and what metric it may carry, and each circuit's own fields -- its name,
// its DIS priority and its hello keys. That last one matters most here,
// because a changed circuit leaves as a delete and comes back as an add, so a
// check this does not reach is one that runs with the circuit already down.
//
// Two things stay outside that line. What only a socket can answer -- that an
// interface is there, that its MTU admits our LSPs -- is not asked here: the
// circuits are opened while the batch is applied (Changes.addCircuit), so a
// circuit the box does not have leaves the reload partially applied for the
// next signal rather than refusing a file whose other keys are fine. And the
// node's running state is not compared at all. Diff is file against file, so a
// prefix or locator an operator added through the management API is one the
// server can still refuse in the middle of the batch.
func Diff(old, next *Config) (Changes, error) {
	// Options is the startup path's validation. Opening the circuits is its
	// one side effect and a restart's job alone, so the probe replaces the
	// opener rather than taking an AF_PACKET socket per interface.
	probe := *next
	probe.OpenCircuit = func(string) (datalink.Transport, []netip.Addr, []netip.Addr, error) { return nil, nil, nil, nil }
	if _, err := probe.Options(); err != nil {
		return Changes{}, err
	}

	ch := Changes{open: next.OpenCircuit}
	ch.DeleteCircuits, ch.AddCircuits = circuitChanges(old, next)

	oldAlgos, err := flexAlgoSet(old)
	if err != nil {
		return Changes{}, err
	}
	newAlgos, err := flexAlgoSet(next)
	if err != nil {
		return Changes{}, err
	}
	// A definition that changed is deleted and re-added: the runtime API has
	// no update for one, and a changed priority or metric type is a new
	// definition to the rest of the area either way.
	for algo, fa := range oldAlgos {
		if n, ok := newAlgos[algo]; !ok || n != fa {
			ch.DeleteFlexAlgos = append(ch.DeleteFlexAlgos, algo)
		}
	}
	for algo, fa := range newAlgos {
		if o, ok := oldAlgos[algo]; !ok || o != fa {
			ch.AddFlexAlgos = append(ch.AddFlexAlgos, fa)
		}
	}

	oldLocs, err := locatorSet(old)
	if err != nil {
		return Changes{}, err
	}
	newLocs, err := locatorSet(next)
	if err != nil {
		return Changes{}, err
	}
	// A locator bound to an algorithm that is being re-added goes with it,
	// unchanged though it is: the server refuses to delete a Flexible
	// Algorithm while a locator still names it (DeleteFlexAlgo), so the
	// locator has to step aside and come back after.
	for prefix, algo := range oldLocs {
		if n, ok := newLocs[prefix]; !ok || n != algo || slices.Contains(ch.DeleteFlexAlgos, algo) {
			ch.DeleteLocators = append(ch.DeleteLocators, prefix)
		}
	}
	for prefix, algo := range newLocs {
		if o, ok := oldLocs[prefix]; !ok || o != algo || slices.ContainsFunc(ch.AddFlexAlgos, func(fa server.FlexAlgoConfig) bool { return fa.Algo == algo }) {
			ch.AddLocators = append(ch.AddLocators, server.SRv6LocatorConfig{Prefix: prefix, Algo: algo})
		}
	}

	oldPrefixes, err := prefixSet(old)
	if err != nil {
		return Changes{}, err
	}
	newPrefixes, err := prefixSet(next)
	if err != nil {
		return Changes{}, err
	}
	// A metric change is likewise a withdrawal and a re-advertisement: the
	// server rejects adding a prefix it already originates.
	for prefix, metric := range oldPrefixes {
		if n, ok := newPrefixes[prefix]; !ok || n != metric {
			ch.DeletePrefixes = append(ch.DeletePrefixes, prefix)
		}
	}
	for prefix, metric := range newPrefixes {
		if o, ok := oldPrefixes[prefix]; !ok || o != metric {
			ch.AddPrefixes = append(ch.AddPrefixes, server.AdvertisedPrefix{Prefix: prefix, Metric: metric})
		}
	}

	// Map iteration order is random; a reload that applies the same file twice
	// must issue the same calls in the same order.
	slices.Sort(ch.DeleteFlexAlgos)
	slices.SortFunc(ch.AddFlexAlgos, func(a, b server.FlexAlgoConfig) int { return int(a.Algo) - int(b.Algo) })
	slices.SortFunc(ch.DeleteLocators, func(a, b netip.Prefix) int { return a.Compare(b) })
	slices.SortFunc(ch.AddLocators, func(a, b server.SRv6LocatorConfig) int { return a.Prefix.Compare(b.Prefix) })
	slices.SortFunc(ch.DeletePrefixes, func(a, b netip.Prefix) int { return a.Compare(b) })
	slices.SortFunc(ch.AddPrefixes, func(a, b server.AdvertisedPrefix) int { return a.Prefix.Compare(b.Prefix) })

	for _, f := range restartOnly {
		if !reflect.DeepEqual(f.of(old), f.of(next)) {
			ch.Ignored = append(ch.Ignored, f.key)
		}
	}
	return ch, nil
}

// circuitChanges is the difference between two circuit lists, as the calls that
// apply it. A circuit is identified by its interface name, and one whose
// definition changed is a deletion and an addition: there is no runtime path
// for a circuit's level, timers, priority, padding or metric, and building one
// would be a mutator per field, each with a protocol consequence of its own.
// Nor would it buy much — almost every field takes the adjacency down anyway
// (the level and the hello keys by protocol rule, the hello interval through
// the holding time it advertises, padding through the MTU check the neighbor
// runs), and only the metric would survive a re-origination. Reload warns
// before the drop.
//
// The order within each slice is the file's, which is deterministic; the two
// sets are ordered against each other by Changes' field order.
func circuitChanges(old, next *Config) (del []string, add []CircuitConfig) {
	before := make(map[string]CircuitConfig, len(old.Circuits))
	for _, cc := range old.Circuits {
		before[cc.Interface] = cc
	}
	after := make(map[string]bool, len(next.Circuits))
	for _, cc := range next.Circuits {
		after[cc.Interface] = true
		prev, ok := before[cc.Interface]
		switch {
		case !ok:
			add = append(add, cc)
		case !reflect.DeepEqual(prev, cc):
			del, add = append(del, cc.Interface), append(add, cc)
		}
	}
	for _, cc := range old.Circuits {
		if !after[cc.Interface] {
			del = append(del, cc.Interface)
		}
	}
	return del, add
}

// prefixSet returns the configured prefixes keyed by their masked form — the
// key the RIB, the FIB and the runtime API all agree on, so the same subnet
// written two ways is one prefix.
func prefixSet(c *Config) (map[netip.Prefix]uint32, error) {
	out := make(map[netip.Prefix]uint32, len(c.Prefixes))
	for _, p := range c.Prefixes {
		prefix, err := netip.ParsePrefix(p.Prefix)
		if err != nil {
			return nil, fmt.Errorf("prefix %q: %w", p.Prefix, err)
		}
		out[prefix.Masked()] = p.metric()
	}
	return out, nil
}

// locatorSet returns every configured SRv6 locator keyed by masked prefix,
// mapped to the algorithm it is advertised for: the srv6 list is algorithm 0,
// and a flex-algo's own locator is that algorithm's.
func locatorSet(c *Config) (map[netip.Prefix]uint8, error) {
	out := map[netip.Prefix]uint8{}
	if c.SRv6 != nil {
		for _, l := range c.SRv6.Locators {
			prefix, err := netip.ParsePrefix(l)
			if err != nil {
				return nil, fmt.Errorf("srv6 locator %q: %w", l, err)
			}
			out[prefix.Masked()] = 0
		}
	}
	for _, fa := range c.FlexAlgo {
		if fa.Locator == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(fa.Locator)
		if err != nil {
			return nil, fmt.Errorf("flex-algo %d locator %q: %w", fa.Algo, fa.Locator, err)
		}
		out[prefix.Masked()] = fa.Algo
	}
	return out, nil
}

// flexAlgoSet returns the configured Flexible Algorithms keyed by number, in
// the form the runtime API takes.
func flexAlgoSet(c *Config) (map[uint8]server.FlexAlgoConfig, error) {
	out := make(map[uint8]server.FlexAlgoConfig, len(c.FlexAlgo))
	for _, fa := range c.FlexAlgo {
		mt, err := flexAlgoMetricType(fa.MetricType)
		if err != nil {
			return nil, fmt.Errorf("flex-algo %d: %w", fa.Algo, err)
		}
		out[fa.Algo] = server.FlexAlgoConfig{
			Algo:                fa.Algo,
			MetricType:          mt,
			Priority:            fa.Priority,
			AdvertiseDefinition: fa.Advertise,
		}
	}
	return out, nil
}

// applyTimeout bounds a reload's calls into the server, and reportTimeout the
// one call that records how the reload went. Both are generous: the management
// loop answers in microseconds unless something is wrong, and the point is to
// fail a wedged reload loudly rather than to police latency. They are variables
// so a test can shorten them; nothing else writes them.
var (
	applyTimeout  = 30 * time.Second
	reportTimeout = 5 * time.Second
)

// Reload re-reads path, applies the part of the difference the runtime API
// expresses, and logs every other difference by name. It is what a daemon
// wires SIGHUP to; everything it applies goes through the server's public
// methods, so the Serve loop remains the only writer of protocol state.
//
// It returns the configuration the daemon is now running: the file's values
// for the keys that were applied, and the running ones for the keys that were
// not. Keeping the unapplied keys is what makes a second SIGHUP name them
// again rather than treat a file the daemon never adopted as the truth.
//
// A file that will not load, will not parse or will not validate leaves the
// daemon exactly as it was, and is returned as an error rather than ending it:
// a typo in an edited configuration must not take down a running IGP. A call
// the server refuses once the batch has begun is ErrPartiallyApplied, the one
// outcome that does change the node without adopting the file.
func Reload(ctx context.Context, s *server.IsisServer, cur *Config, path string, logger *slog.Logger) (*Config, error) {
	// Counting the reload must not be able to fail one: the management loop
	// may already be shutting down, and a node that applied its file did so
	// whether or not the report landed.
	//
	// It gets its own deadline rather than the apply's, for two reasons that
	// pull the same way. The outcome most worth recording is the one a wedged
	// loop produces, and that is exactly when the apply's context is already
	// done -- sharing it would drop the "partial" the deadline exists to
	// expose. And the calls made before the apply has a deadline at all sit
	// behind the signal handler, so an unbounded one would hold every later
	// SIGHUP for as long as the loop stays wedged.
	report := func(outcome server.ReloadOutcome) {
		rctx, cancel := context.WithTimeout(ctx, reportTimeout)
		defer cancel()
		if err := s.ReportConfigReload(rctx, outcome); err != nil {
			logger.Debug("configuration reload: outcome not recorded", "outcome", outcome, "error", err)
		}
	}
	// The same bounded, non-fatal shape, for the count of what the reload left
	// in the file. It is separate from report because it is known later: a
	// file that will not load has an outcome but nothing to count.
	reportUnapplied := func(n int) {
		rctx, cancel := context.WithTimeout(ctx, reportTimeout)
		defer cancel()
		if err := s.ReportConfigReloadUnapplied(rctx, n); err != nil {
			logger.Debug("configuration reload: unapplied count not recorded", "count", n, "error", err)
		}
	}
	next, err := Load(path)
	if err != nil {
		report(server.ReloadRefused)
		return cur, err
	}
	// The transport seam belongs to the running configuration, never to the
	// file: Load cannot set it, and a reload that dropped it would open the
	// circuits it adds with AF_PACKET under an embedder that supplied its own.
	next.OpenCircuit = cur.OpenCircuit
	ch, err := Diff(cur, next)
	if err != nil {
		report(server.ReloadRefused)
		return cur, err
	}
	for _, key := range ch.Ignored {
		logger.Warn("configuration reload: this change needs a restart and was not applied", "key", key)
	}
	// Counted as well as logged, because the difference outlives the log line.
	// The file keeps it, so the next restart applies it -- and Restart= makes
	// that restart something nobody has to ask for. See ConfigReloadUnapplied.
	// The calls the server refuses are added to it below: a circuit the box
	// does not have is the same kind of divergence as a key that needs a
	// restart, and the worse one, because the next restart does not adopt it --
	// it fails on it.
	//
	// Deferred so it goes out however the apply below ends, and after the
	// outcome rather than in front of it: the count is the same either way,
	// and a reload must not spend a second deadline before it applies anything.
	unapplied := len(ch.Ignored)
	defer func() { reportUnapplied(unapplied) }()
	// A deadline, because the caller's context is the daemon's lifetime: every
	// call below queues behind the Serve loop, so a loop wedged on a slow sink
	// would otherwise hold the reload — and the signal handler behind it —
	// until the process ends, with nothing said.
	applyCtx, cancel := context.WithTimeout(ctx, applyTimeout)
	defer cancel()
	if errs := ch.apply(applyCtx, s, logger); len(errs) > 0 {
		// No rollback: undoing what landed would need the inverse of every
		// mutator, and the joined error already names every call the server
		// refused. What is owed instead is honesty — the baseline stays where
		// it was, so the next SIGHUP re-diffs the whole change and reports it
		// again, rather than recording a file the node never adopted as the
		// truth.
		unapplied += len(errs)
		report(server.ReloadPartial)
		return cur, fmt.Errorf("%w: %w", ErrPartiallyApplied, errors.Join(errs...))
	}
	report(server.ReloadApplied)

	running := *cur
	running.Prefixes, running.SRv6, running.FlexAlgo = next.Prefixes, next.SRv6, next.FlexAlgo
	running.Circuits = next.Circuits
	return &running, nil
}

// apply pushes the changes through the server's runtime API, in the field
// order Changes documents, and returns every refusal rather than the first.
// The batch order is fixed and Diff derives the same batch from the same file
// every time, so returning at the first refusal would put every call behind it
// out of reach of any number of signals. Issuing them all costs a refusal only
// the call it refuses. The refusals are returned one per call and not joined,
// because the count is the reload's distance from the file and Reload reports
// it (ConfigReloadUnapplied).
//
// The file is authoritative for what it names, so a call the server refuses
// because the node is already in the state it asks for (server.ErrAlreadyInState)
// is this reload succeeding at that call. That is the whole recovery path: Diff
// is file against file, so a reload a refusal left part applied is retried by
// re-issuing every call in the batch, and without this the calls that already
// landed are refused again, identically, for as long as the operator keeps
// signalling. A refusal that reports anything else -- a prefix present at
// another metric, a locator bound to another algorithm -- is still an error,
// because the file asks for a value the node does not have.
func (ch Changes) apply(ctx context.Context, s *server.IsisServer, logger *slog.Logger) []error {
	var errs []error
	call := func(err error) {
		if err != nil && !errors.Is(err, server.ErrAlreadyInState) {
			errs = append(errs, err)
		}
	}
	for _, name := range ch.DeleteCircuits {
		if ch.rebuilds(name) {
			continue // issued by addCircuit, and only if the node still needs it
		}
		call(s.DeleteCircuit(ctx, name))
	}
	for _, prefix := range ch.DeleteLocators {
		call(s.DeleteLocator(ctx, prefix))
	}
	for _, algo := range ch.DeleteFlexAlgos {
		call(s.DeleteFlexAlgo(ctx, algo))
	}
	for _, fa := range ch.AddFlexAlgos {
		call(s.AddFlexAlgo(ctx, fa))
	}
	for _, lc := range ch.AddLocators {
		call(s.AddLocator(ctx, lc))
	}
	for _, prefix := range ch.DeletePrefixes {
		call(s.DeletePrefix(ctx, prefix))
	}
	for _, p := range ch.AddPrefixes {
		call(s.AddPrefix(ctx, p))
	}
	for _, cc := range ch.AddCircuits {
		call(ch.addCircuit(ctx, s, cc, logger))
	}
	return errs
}

// rebuilds reports whether a circuit is named by both halves of the batch,
// which is the shape circuitChanges gives a circuit whose definition changed.
func (ch Changes) rebuilds(name string) bool {
	return slices.Contains(ch.DeleteCircuits, name) &&
		slices.ContainsFunc(ch.AddCircuits, func(cc CircuitConfig) bool { return cc.Interface == name })
}

// addCircuit puts one circuit into the shape the file gives it: it opens a
// transport and hands it to the server, and for a circuit that is being
// rebuilt it issues the deletion between two attempts at that. An interface
// that cannot be opened costs this circuit and nothing else: apply issues the
// whole batch, so the rest still lands, Reload reports ErrPartiallyApplied and
// keeps its baseline, and the next signal re-diffs and tries this one again --
// which is what makes "that NIC comes up in a minute" resolve itself.
//
// The addition is also what says whether a rebuild is still owed, which is why
// the deletion is here rather than at the head of the batch. The server
// answers ErrAlreadyInState for a running circuit identical in every field and
// names the fields when it is not (server.AddCircuit), so asking first is
// asking the node. Deleting up front instead would rebuild the circuit on
// every signal: Diff is file against file and a refused reload keeps its
// baseline, so the same delete-plus-add is re-derived unchanged, and the
// adjacencies would drop once per SIGHUP over a circuit already in the file's
// shape, for as long as some unrelated call in the batch keeps failing. An
// addition that failed before it reached the server -- an interface that is
// not there -- takes the delete path too: the file asks for a circuit the node
// does not have either way, and the running one is on an interface the box no
// longer opens.
//
// AddCircuit takes ownership of the transport on every path, refusals
// included, so there is nothing to close here -- and nothing that may be
// closed here, the refused first attempt included. A management operation's
// context bounds the caller's wait and not the operation, so an addition still
// queued when applyTimeout expires runs afterwards: closing on that error
// would hand the server a circuit on a socket this reload had already closed.
func (ch Changes) addCircuit(ctx context.Context, s *server.IsisServer, cc CircuitConfig, logger *slog.Logger) error {
	add := func() error {
		open := ch.open
		if open == nil {
			open = defaultOpenCircuit
		}
		cfg, err := cc.circuit(open)
		if err != nil {
			return err
		}
		cfg.ConnectedPrefixes = connectedPrefixes(cc.Interface)
		return s.AddCircuit(ctx, cfg)
	}
	err := add()
	if err == nil || errors.Is(err, server.ErrAlreadyInState) || !ch.rebuilds(cc.Interface) {
		return err
	}
	// The adjacencies go with the circuit, so the operator is told before they
	// drop rather than reading it off a neighbor count -- and only on the
	// signal that drops them.
	logger.Warn("configuration reload: this circuit is rebuilt to apply the change, and its adjacencies will drop", "circuit", cc.Interface)
	if err := s.DeleteCircuit(ctx, cc.Interface); err != nil && !errors.Is(err, server.ErrAlreadyInState) {
		return err
	}
	return add()
}
