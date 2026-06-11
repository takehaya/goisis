// Command goisis is the CLI client for goisisd.
package main

import (
	"net/http"
	"os"

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
		Use:          "goisis",
		Short:        "CLI client for the goisisd IS-IS daemon",
		SilenceUsage: true,
	}
	cmd.PersistentFlags().StringVarP(&addr, "addr", "u", "http://127.0.0.1:50051", "goisisd API base URL")
	cmd.AddCommand(newGlobalCmd(&addr), newVersionCmd())
	return cmd
}

func newClient(addr string) goisisv1alpha1connect.IsisServiceClient {
	return goisisv1alpha1connect.NewIsisServiceClient(http.DefaultClient, addr)
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
			cmd.Printf("goisisd version: %s\n", res.Msg.GetGlobal().GetVersion())
			return nil
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
