// Command goisis is the CLI client for goisisd.
package main

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"connectrpc.com/connect"
	"github.com/spf13/cobra"

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
	cmd.PersistentFlags().StringVarP(&addr, "addr", "u", "http://127.0.0.1:50051", "goisisd API base URL")
	cmd.AddCommand(
		newGlobalCmd(&addr),
		newCircuitCmd(&addr),
		newNeighborCmd(&addr),
		newDatabaseCmd(&addr),
		newRouteCmd(&addr),
		newLocatorCmd(&addr),
		newFlexAlgoCmd(&addr),
		newMonitorCmd(&addr),
		newVersionCmd(),
	)
	return cmd
}

func newClient(addr string) goisisv1connect.IsisServiceClient {
	return goisisv1connect.NewIsisServiceClient(http.DefaultClient, addr)
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
			g := res.Msg.GetGlobal()
			cmd.Printf("version:   %s\nsystem-id: %s\n", g.GetVersion(), g.GetSystemId())
			return nil
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
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintln(w, "INTERFACE\tTYPE\tLEVELS\tPRIORITY\tMETRIC")
			for _, c := range res.Msg.GetCircuits() {
				_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%d\n", c.GetInterface(), circuitType(c), circuitLevels(c), c.GetPriority(), c.GetMetric())
			}
			return w.Flush()
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
	return &cobra.Command{
		Use:     "neighbor",
		Aliases: []string{"neighbors", "adjacency"},
		Short:   "List IS-IS adjacencies",
		RunE: func(cmd *cobra.Command, _ []string) error {
			res, err := newClient(*addr).ListAdjacencies(cmd.Context(), connect.NewRequest(&goisisv1.ListAdjacenciesRequest{}))
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintln(w, "SYSTEM-ID\tINTERFACE\tLEVEL\tSTATE\tSNPA\tHOLD")
			for _, a := range res.Msg.GetAdjacencies() {
				_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\n",
					a.GetSystemId(), a.GetInterface(), levelStr(a.GetLevel()), a.GetState(), a.GetSnpa(), a.GetHoldingTime())
			}
			return w.Flush()
		},
	}
}

func newDatabaseCmd(addr *string) *cobra.Command {
	return &cobra.Command{
		Use:     "database",
		Aliases: []string{"lsdb"},
		Short:   "Show the link-state database",
		RunE: func(cmd *cobra.Command, _ []string) error {
			res, err := newClient(*addr).GetLsdb(cmd.Context(), connect.NewRequest(&goisisv1.GetLsdbRequest{}))
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintln(w, "LSP-ID\tLEVEL\tSEQ\tLIFETIME\tCHECKSUM\tOWN")
			for _, l := range res.Msg.GetLsps() {
				own := ""
				if l.GetOwn() {
					own = "*"
				}
				_, _ = fmt.Fprintf(w, "%s\t%s\t0x%08x\t%d\t0x%04x\t%s\n",
					l.GetLspId(), levelStr(l.GetLevel()), l.GetSequenceNumber(), l.GetRemainingLifetime(), l.GetChecksum(), own)
			}
			return w.Flush()
		},
	}
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
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintln(w, "PREFIX\tLEVEL\tALGO\tMETRIC\tNEXT-HOPS")
			for _, r := range res.Msg.GetRoutes() {
				_, _ = fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%s\n", r.GetPrefix(), levelStr(r.GetLevel()), r.GetAlgorithm(), r.GetMetric(), nextHops(r))
			}
			return w.Flush()
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
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintln(w, "PREFIX\tALGO\tEND-SID")
			for _, l := range res.Msg.GetLocators() {
				_, _ = fmt.Fprintf(w, "%s\t%d\t%s\n", l.GetPrefix(), l.GetAlgorithm(), l.GetEndSid())
			}
			return w.Flush()
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
	return &cobra.Command{
		Use:   "monitor",
		Short: "Stream adjacency and route changes",
		RunE: func(cmd *cobra.Command, _ []string) error {
			stream, err := newClient(*addr).WatchEvent(cmd.Context(), connect.NewRequest(&goisisv1.WatchEventRequest{}))
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
