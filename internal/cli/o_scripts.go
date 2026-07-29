// Copyright 2026 joelcodess. Licensed under Apache-2.0. See LICENSE.

package cli

import (
	"github.com/spf13/cobra"
)

func newOScriptsCmd(flags *rootFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scripts",
		Short: "Manage scripts",
	}

	cmd.AddCommand(newOScriptsDeleteCmd(flags))
	cmd.AddCommand(newOScriptsQueryCmd(flags))
	return cmd
}
