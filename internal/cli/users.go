// Copyright 2026 joelcodess. Licensed under Apache-2.0. See LICENSE.

package cli

import (
	"github.com/spf13/cobra"
)

func newUsersCmd(flags *rootFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:    "users",
		Short:  "Manage users",
		Hidden: true,
	}

	cmd.AddCommand(newUsersCreateCmd(flags))
	cmd.AddCommand(newUsersDeleteCmd(flags))
	cmd.AddCommand(newUsersUpdateCmd(flags))
	return cmd
}
