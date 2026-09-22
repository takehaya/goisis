// Command goisis is the CLI client for goisisd.
package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"

	"connectrpc.com/connect"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	goisisv1 "github.com/takehaya/goisis/gen/goisis/v1"
	"github.com/takehaya/goisis/gen/goisis/v1/goisisv1connect"
	"github.com/takehaya/goisis/internal/version"
	"github.com/takehaya/goisis/pkg/packet"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	var addr string
	cmd := &cobra.Command{
		Use:               "goisis",
		Short:             "CLI client for the goisisd IS-IS daemon",
		SilenceUsage:      true,
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
	}
	cmd.PersistentFlags().StringVarP(&addr, "addr", "u", "http://127.0.0.1:50051", "goisisd API base URL, or unix:///absolute/path for a unix socket")
	cmd.PersistentFlags().StringP("output", "o", "table", "output format: table or json")
	cmd.AddCommand(
		newGlobalCmd(&addr),
		newCircuitCmd(&addr),
		newNeighborCmd(&addr),
		newDatabaseCmd(&addr),
		newRouteCmd(&addr),
		newPrefixCmd(&addr),
		newOverloadCmd(&addr),
		newLocatorCmd(&addr),
		newFlexAlgoCmd(&addr),
		newMonitorCmd(&addr),
		newVersionCmd(),
	)
	return cmd
}

func newClient(addr string) goisisv1connect.IsisServiceClient {
	httpClient, baseURL, err := newHTTPClient(addr)
	if err != nil {
		// Every command builds its client inline, so there is no earlier
		// place to return this; let the first RPC fail on the raw address.
		httpClient, baseURL = http.DefaultClient, addr
	}
	return goisisv1connect.NewIsisServiceClient(httpClient, baseURL)
}

// newHTTPClient returns the transport for addr and the base URL to give the
// Connect client. For a "unix://" address every request is dialled over the
// socket path, so the base URL only has to be a well-formed placeholder.
func newHTTPClient(addr string) (*http.Client, string, error) {
	path, ok := strings.CutPrefix(addr, "unix://")
	if !ok {
		return http.DefaultClient, addr, nil
	}
	if !filepath.IsAbs(path) {
		return nil, "", fmt.Errorf("unix socket path must be absolute: %q", addr)
	}
	var d net.Dialer
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return d.DialContext(ctx, "unix", path)
		},
	}}, "http://unix", nil
}

// printResponse renders an RPC response: the command's own table, or the whole
// response message as JSON under "-o json". The format is read back off the
// command rather than threaded through every constructor, so a subcommand sees
// the root's persistent flag.
func printResponse(cmd *cobra.Command, msg proto.Message, table func() error) error {
	switch format, _ := cmd.Flags().GetString("output"); format {
	case "json":
		b, err := protojson.MarshalOptions{Multiline: true, EmitUnpopulated: false}.Marshal(msg)
		if err != nil {
			return err
		}
		cmd.Println(string(b))
		return nil
	case "table", "":
		return table()
	default:
		return fmt.Errorf("unknown output format %q (want table or json)", format)
	}
}

func levelStr(l goisisv1.Level) string {
	switch l {
	case goisisv1.Level_LEVEL_1:
		return "L1"
	case goisisv1.Level_LEVEL_2:
		return "L2"
	default:
		return "-"
	}
}

func newGlobalCmd(addr *string) *cobra.Command {
	return &cobra.Command{
		Use:   "global",
		Short: "Show instance-wide daemon state",
		RunE: func(cmd *cobra.Command, _ []string) error {
			res, err := newClient(*addr).GetIsis(cmd.Context(), connect.NewRequest(&goisisv1.GetIsisRequest{}))
			if err != nil {
				return err
			}
			return printResponse(cmd, res.Msg, func() error {
				g := res.Msg.GetGlobal()
				cmd.Printf("version:   %s\nsystem-id: %s\noverload:  %t\n", g.GetVersion(), g.GetSystemId(), g.GetOverload())
				return nil
			})
		},
	}
}

func newCircuitCmd(addr *string) *cobra.Command {
	return &cobra.Command{
		Use:     "circuit",
		Aliases: []string{"circuits", "interface"},
		Short:   "List circuits",
		RunE: func(cmd *cobra.Command, _ []string) error {
			res, err := newClient(*addr).ListCircuits(cmd.Context(), connect.NewRequest(&goisisv1.ListCircuitsRequest{}))
			if err != nil {
				return err
			}
			return printResponse(cmd, res.Msg, func() error {
				w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
				_, _ = fmt.Fprintln(w, "INTERFACE\tTYPE\tLEVELS\tPRIORITY\tMETRIC")
				for _, c := range res.Msg.GetCircuits() {
					_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\n", c.GetInterface(), circuitType(c), circuitLevels(c), c.GetPriority(), c.GetMetric())
				}
				return w.Flush()
			})
		},
	}
}

func circuitType(c *goisisv1.Circuit) string {
	if c.GetPointToPoint() {
		return "p2p"
	}
	return "lan"
}

func circuitLevels(c *goisisv1.Circuit) string {
	switch {
	case c.GetLevel1() && c.GetLevel2():
		return "L1L2"
	case c.GetLevel2():
		return "L2"
	default:
		return "L1"
	}
}

func newNeighborCmd(addr *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "neighbor",
		Aliases: []string{"neighbors", "adjacency"},
		Short:   "List IS-IS adjacencies",
		RunE: func(cmd *cobra.Command, _ []string) error {
			res, err := newClient(*addr).ListAdjacencies(cmd.Context(), connect.NewRequest(&goisisv1.ListAdjacenciesRequest{}))
			if err != nil {
				return err
			}
			return printResponse(cmd, res.Msg, func() error {
				w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
				_, _ = fmt.Fprintln(w, "SYSTEM-ID\tHOSTNAME\tINTERFACE\tLEVEL\tSTATE\tSNPA\tHOLD")
				for _, a := range res.Msg.GetAdjacencies() {
					_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%d\n",
						a.GetSystemId(), a.GetHostname(), a.GetInterface(), levelStr(a.GetLevel()), a.GetState(), a.GetSnpa(), a.GetHoldingTime())
				}
				return w.Flush()
			})
		},
	}
	cmd.AddCommand(newNeighborClearCmd(addr))
	return cmd
}

func newNeighborClearCmd(addr *string) *cobra.Command {
	var iface, systemID string
	cmd := &cobra.Command{
		Use:   "clear",
		Short: "Tear down adjacencies on a circuit so hellos re-form them",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := newClient(*addr).ClearAdjacency(cmd.Context(), connect.NewRequest(&goisisv1.ClearAdjacencyRequest{
				Interface: iface,
				SystemId:  systemID,
			}))
			return err
		},
	}
	cmd.Flags().StringVar(&iface, "interface", "", "circuit whose adjacencies to clear")
	cmd.Flags().StringVar(&systemID, "system-id", "", "clear only this neighbor (dotted, e.g. 0000.0000.0001)")
	_ = cmd.MarkFlagRequired("interface")
	return cmd
}

func newPrefixCmd(addr *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "prefix",
		Short: "Configure the prefixes this node originates",
	}
	cmd.AddCommand(newPrefixAddCmd(addr), newPrefixDeleteCmd(addr))
	return cmd
}

func newPrefixAddCmd(addr *string) *cobra.Command {
	var metric uint32
	cmd := &cobra.Command{
		Use:   "add <prefix>",
		Short: "Originate a prefix in this node's LSP",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := newClient(*addr).AddPrefix(cmd.Context(), connect.NewRequest(&goisisv1.AddPrefixRequest{
				Prefix: args[0],
				Metric: metric,
			}))
			return err
		},
	}
	cmd.Flags().Uint32Var(&metric, "metric", 10, "wide metric advertised with the prefix")
	return cmd
}

func newPrefixDeleteCmd(addr *string) *cobra.Command {
	return &cobra.Command{
		Use:     "delete <prefix>",
		Aliases: []string{"del", "remove"},
		Short:   "Withdraw a prefix this node originates",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := newClient(*addr).DeletePrefix(cmd.Context(), connect.NewRequest(&goisisv1.DeletePrefixRequest{
				Prefix: args[0],
			}))
			return err
		},
	}
}

func newOverloadCmd(addr *string) *cobra.Command {
	return &cobra.Command{
		Use:   "overload on|off",
		Short: "Set or clear the overload bit by hand (maintenance)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			on, err := parseOnOff(args[0])
			if err != nil {
				return err
			}
			_, err = newClient(*addr).SetOverload(cmd.Context(), connect.NewRequest(&goisisv1.SetOverloadRequest{
				Overload: on,
			}))
			return err
		},
	}
}

func parseOnOff(s string) (bool, error) {
	switch s {
	case "on":
		return true, nil
	case "off":
		return false, nil
	default:
		return false, fmt.Errorf("unknown argument %q (want on or off)", s)
	}
}

func newDatabaseCmd(addr *string) *cobra.Command {
	var detail bool
	cmd := &cobra.Command{
		Use:     "database",
		Aliases: []string{"lsdb"},
		Short:   "Show the link-state database",
		RunE: func(cmd *cobra.Command, _ []string) error {
			res, err := newClient(*addr).GetLsdb(cmd.Context(), connect.NewRequest(&goisisv1.GetLsdbRequest{}))
			if err != nil {
				return err
			}
			return printResponse(cmd, res.Msg, func() error {
				w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
				_, _ = fmt.Fprintln(w, "LSP-ID\tHOSTNAME\tLEVEL\tSEQ\tLIFETIME\tCHECKSUM\tOWN")
				for _, l := range res.Msg.GetLsps() {
					own := ""
					if l.GetOwn() {
						own = "*"
					}
					_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t0x%08x\t%d\t0x%04x\t%s\n",
						l.GetLspId(), l.GetHostname(), levelStr(l.GetLevel()), l.GetSequenceNumber(), l.GetRemainingLifetime(), l.GetChecksum(), own)
					if !detail {
						continue
					}
					// A line without tabs ends the tabwriter column block, so
					// under --detail each row aligns against itself rather than
					// against the whole table.
					for _, t := range l.GetTlvs() {
						_, _ = fmt.Fprintf(w, "  %s\n", t)
					}
				}
				return w.Flush()
			})
		},
	}
	cmd.Flags().BoolVarP(&detail, "detail", "d", false, "print each LSP's TLVs under its row")
	return cmd
}

func newRouteCmd(addr *string) *cobra.Command {
	return &cobra.Command{
		Use:   "route",
		Short: "List computed routes",
		RunE: func(cmd *cobra.Command, _ []string) error {
			res, err := newClient(*addr).ListRoutes(cmd.Context(), connect.NewRequest(&goisisv1.ListRoutesRequest{}))
			if err != nil {
				return err
			}
			return printResponse(cmd, res.Msg, func() error {
				w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
				_, _ = fmt.Fprintln(w, "PREFIX\tLEVEL\tALGO\tMETRIC\tNEXT-HOPS")
				for _, r := range res.Msg.GetRoutes() {
					_, _ = fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%s\n", r.GetPrefix(), levelStr(r.GetLevel()), r.GetAlgorithm(), r.GetMetric(), nextHops(r))
				}
				return w.Flush()
			})
		},
	}
}

func newLocatorCmd(addr *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "locator",
		Short: "List or configure advertised SRv6 locators",
		RunE: func(cmd *cobra.Command, _ []string) error {
			res, err := newClient(*addr).ListLocators(cmd.Context(), connect.NewRequest(&goisisv1.ListLocatorsRequest{}))
			if err != nil {
				return err
			}
			return printResponse(cmd, res.Msg, func() error {
				w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
				_, _ = fmt.Fprintln(w, "PREFIX\tALGO\tEND-SID")
				for _, l := range res.Msg.GetLocators() {
					_, _ = fmt.Fprintf(w, "%s\t%d\t%s\n", l.GetPrefix(), l.GetAlgorithm(), l.GetEndSid())
				}
				return w.Flush()
			})
		},
	}
	cmd.AddCommand(newLocatorAddCmd(addr), newLocatorDeleteCmd(addr))
	return cmd
}

func newLocatorAddCmd(addr *string) *cobra.Command {
	var algo uint32
	cmd := &cobra.Command{
		Use:   "add <prefix>",
		Short: "Advertise a new SRv6 locator",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := newClient(*addr).AddLocator(cmd.Context(), connect.NewRequest(&goisisv1.AddLocatorRequest{
				Prefix:    args[0],
				Algorithm: algo,
			}))
			return err
		},
	}
	cmd.Flags().Uint32Var(&algo, "algo", 0, "bind the locator to a Flexible Algorithm (128-255); 0 = normal SPF")
	return cmd
}

func newLocatorDeleteCmd(addr *string) *cobra.Command {
	return &cobra.Command{
		Use:     "delete <prefix>",
		Aliases: []string{"del", "remove"},
		Short:   "Withdraw an advertised SRv6 locator",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := newClient(*addr).DeleteLocator(cmd.Context(), connect.NewRequest(&goisisv1.DeleteLocatorRequest{
				Prefix: args[0],
			}))
			return err
		},
	}
}

func newFlexAlgoCmd(addr *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "flex-algo",
		Aliases: []string{"flexalgo"},
		Short:   "List or configure Flexible Algorithms",
		RunE: func(cmd *cobra.Command, _ []string) error {
			res, err := newClient(*addr).ListFlexAlgos(cmd.Context(), connect.NewRequest(&goisisv1.ListFlexAlgosRequest{}))
			if err != nil {
				return err
			}
			return printResponse(cmd, res.Msg, func() error {
				w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
				_, _ = fmt.Fprintln(w, "ALGO\tLEVEL\tMETRIC-TYPE\tPRIORITY\tADVERTISER\tPARTICIPANTS")
				for _, fa := range res.Msg.GetFlexAlgos() {
					mt, prio, adv := "-", "-", "-"
					if d := fa.GetDefinition(); d != nil {
						mt = metricTypeStr(d.GetMetricType())
						prio = fmt.Sprintf("%d", d.GetPriority())
						adv = d.GetAdvertiser()
					}
					_, _ = fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\n",
						fa.GetAlgorithm(), levelStr(fa.GetLevel()), mt, prio, adv, strings.Join(fa.GetParticipants(), ", "))
				}
				return w.Flush()
			})
		},
	}
	cmd.AddCommand(newFlexAlgoAddCmd(addr), newFlexAlgoDeleteCmd(addr))
	return cmd
}

func newFlexAlgoAddCmd(addr *string) *cobra.Command {
	var (
		metricType string
		priority   uint32
		advertise  bool
	)
	cmd := &cobra.Command{
		Use:   "add <algo>",
		Short: "Participate in a Flexible Algorithm (128-255)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			algo, err := parseUint8(args[0])
			if err != nil {
				return fmt.Errorf("algo: %w", err)
			}
			mt, err := parseMetricType(metricType)
			if err != nil {
				return err
			}
			_, err = newClient(*addr).AddFlexAlgo(cmd.Context(), connect.NewRequest(&goisisv1.AddFlexAlgoRequest{
				Algorithm:           uint32(algo),
				MetricType:          uint32(mt),
				Priority:            priority,
				AdvertiseDefinition: advertise,
			}))
			return err
		},
	}
	cmd.Flags().StringVar(&metricType, "metric-type", "igp", "metric type: igp, delay, or te")
	cmd.Flags().Uint32Var(&priority, "priority", 0, "advertised election priority")
	cmd.Flags().BoolVar(&advertise, "advertise", false, "advertise the Flex-Algo definition (FAD)")
	return cmd
}

func newFlexAlgoDeleteCmd(addr *string) *cobra.Command {
	return &cobra.Command{
		Use:     "delete <algo>",
		Aliases: []string{"del", "remove"},
		Short:   "Stop participating in a Flexible Algorithm",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			algo, err := parseUint8(args[0])
			if err != nil {
				return fmt.Errorf("algo: %w", err)
			}
			_, err = newClient(*addr).DeleteFlexAlgo(cmd.Context(), connect.NewRequest(&goisisv1.DeleteFlexAlgoRequest{
				Algorithm: uint32(algo),
			}))
			return err
		},
	}
}

func parseUint8(s string) (uint8, error) {
	v, err := strconv.ParseUint(s, 10, 8)
	if err != nil {
		return 0, err
	}
	return uint8(v), nil
}

func parseMetricType(s string) (uint8, error) {
	switch s {
	case "igp", "":
		return packet.FlexAlgoMetricIGP, nil
	case "delay":
		return packet.FlexAlgoMetricMinDelay, nil
	case "te":
		return packet.FlexAlgoMetricTE, nil
	default:
		return 0, fmt.Errorf("unknown metric type %q (want igp, delay, or te)", s)
	}
}

func metricTypeStr(mt uint32) string {
	switch uint8(mt) {
	case packet.FlexAlgoMetricIGP:
		return "igp"
	case packet.FlexAlgoMetricMinDelay:
		return "delay"
	case packet.FlexAlgoMetricTE:
		return "te"
	default:
		return fmt.Sprintf("%d", mt)
	}
}

func nextHops(r *goisisv1.Route) string {
	out := ""
	for i, nh := range r.GetNextHops() {
		if i > 0 {
			out += ", "
		}
		out += nh.GetGateway() + " (" + nh.GetInterface() + ")"
	}
	return out
}

func newMonitorCmd(addr *string) *cobra.Command {
	var initial bool
	cmd := &cobra.Command{
		Use:   "monitor",
		Short: "Stream adjacency and route changes",
		RunE: func(cmd *cobra.Command, _ []string) error {
			stream, err := newClient(*addr).WatchEvent(cmd.Context(),
				connect.NewRequest(&goisisv1.WatchEventRequest{IncludeInitial: initial}))
			if err != nil {
				return err
			}
			for stream.Receive() {
				switch ev := stream.Msg().GetEvent().(type) {
				case *goisisv1.WatchEventResponse_Adjacency:
					a := ev.Adjacency.GetAdjacency()
					cmd.Printf("ADJ  %s %s %s %s\n", a.GetSystemId(), a.GetInterface(), levelStr(a.GetLevel()), a.GetState())
				case *goisisv1.WatchEventResponse_Route:
					r := ev.Route.GetRoute()
					verb := "ROUTE+"
					if ev.Route.GetWithdrawn() {
						verb = "ROUTE-"
					}
					cmd.Printf("%s %s metric=%d %s\n", verb, r.GetPrefix(), r.GetMetric(), nextHops(r))
				}
			}
			return stream.Err()
		},
	}
	cmd.Flags().BoolVar(&initial, "initial", false, "dump the current adjacencies and routes before following changes")
	return cmd
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show CLI version",
		Run: func(cmd *cobra.Command, _ []string) {
			cmd.Println(version.Version)
		},
	}
}
