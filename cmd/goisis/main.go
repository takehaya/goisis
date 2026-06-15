// Command goisis is the CLI client for goisisd.
package main

import (
	"fmt"
	"net/http"
	"os"
	"text/tabwriter"

	"connectrpc.com/connect"
	"github.com/spf13/cobra"

	goisisv1alpha1 "github.com/takehaya/goisis/gen/goisis/v1alpha1"
	"github.com/takehaya/goisis/gen/goisis/v1alpha1/goisisv1alpha1connect"
	"github.com/takehaya/goisis/internal/version"
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
		newMonitorCmd(&addr),
		newVersionCmd(),
	)
	return cmd
}

func newClient(addr string) goisisv1alpha1connect.IsisServiceClient {
	return goisisv1alpha1connect.NewIsisServiceClient(http.DefaultClient, addr)
}

func levelStr(l goisisv1alpha1.Level) string {
	switch l {
	case goisisv1alpha1.Level_LEVEL_1:
		return "L1"
	case goisisv1alpha1.Level_LEVEL_2:
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
			res, err := newClient(*addr).GetIsis(cmd.Context(), connect.NewRequest(&goisisv1alpha1.GetIsisRequest{}))
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
			res, err := newClient(*addr).ListCircuits(cmd.Context(), connect.NewRequest(&goisisv1alpha1.ListCircuitsRequest{}))
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

func circuitType(c *goisisv1alpha1.Circuit) string {
	if c.GetPointToPoint() {
		return "p2p"
	}
	return "lan"
}

func circuitLevels(c *goisisv1alpha1.Circuit) string {
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
			res, err := newClient(*addr).ListAdjacencies(cmd.Context(), connect.NewRequest(&goisisv1alpha1.ListAdjacenciesRequest{}))
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
			res, err := newClient(*addr).GetLsdb(cmd.Context(), connect.NewRequest(&goisisv1alpha1.GetLsdbRequest{}))
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
			res, err := newClient(*addr).ListRoutes(cmd.Context(), connect.NewRequest(&goisisv1alpha1.ListRoutesRequest{}))
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintln(w, "PREFIX\tLEVEL\tMETRIC\tNEXT-HOPS")
			for _, r := range res.Msg.GetRoutes() {
				_, _ = fmt.Fprintf(w, "%s\t%s\t%d\t%s\n", r.GetPrefix(), levelStr(r.GetLevel()), r.GetMetric(), nextHops(r))
			}
			return w.Flush()
		},
	}
}

func nextHops(r *goisisv1alpha1.Route) string {
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
			stream, err := newClient(*addr).WatchEvent(cmd.Context(), connect.NewRequest(&goisisv1alpha1.WatchEventRequest{}))
			if err != nil {
				return err
			}
			for stream.Receive() {
				switch ev := stream.Msg().GetEvent().(type) {
				case *goisisv1alpha1.WatchEventResponse_Adjacency:
					a := ev.Adjacency.GetAdjacency()
					cmd.Printf("ADJ  %s %s %s %s\n", a.GetSystemId(), a.GetInterface(), levelStr(a.GetLevel()), a.GetState())
				case *goisisv1alpha1.WatchEventResponse_Route:
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
