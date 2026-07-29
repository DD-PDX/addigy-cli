// Copyright 2026 joelcodess. Licensed under Apache-2.0. See LICENSE.

// Package mcp — code-orchestration thin surface.
//
// Two tools cover the entire API: <api>_search to discover endpoints, and
// <api>_execute to invoke one. This collapses a large API (50+ endpoints)
// to ~1K tokens of tool definitions while preserving full coverage — the
// agent writes the composition logic in its own sandbox.
//
// Pattern source: Anthropic 2026-04-22 "Building agents that reach
// production systems with MCP" — Cloudflare's MCP server covers ~2,500
// endpoints in roughly 1K tokens via the same search+execute shape.

package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/joelcodess/addigy-cli/internal/client"
	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// RegisterCodeOrchestrationTools registers the two agent-facing tools that
// cover the whole API surface. Called from RegisterTools in place of the
// per-endpoint registrations when MCP.Orchestration is "code".
func RegisterCodeOrchestrationTools(s *server.MCPServer) {
	s.AddTool(
		mcplib.NewTool("addigy_search",
			mcplib.WithDescription("Search the addigy API for endpoints matching a natural-language query. Returns a ranked list of {endpoint_id, method, path, summary} entries. Call this first to find the endpoint to execute."),
			mcplib.WithString("query", mcplib.Required(), mcplib.Description("Natural-language description of what you want to do.")),
			mcplib.WithNumber("limit", mcplib.Description("Max endpoints to return (default 10).")),
		),
		handleCodeOrchSearch,
	)

	s.AddTool(
		mcplib.NewTool("addigy_execute",
			mcplib.WithDescription("Execute one addigy API endpoint by its endpoint_id (from addigy_search). Params are passed as a JSON object; path placeholders and query strings are resolved automatically."),
			mcplib.WithString("endpoint_id", mcplib.Required(), mcplib.Description("Endpoint identifier returned by addigy_search (e.g., \"users.list\").")),
			mcplib.WithObject("params", mcplib.Description("Parameters for the endpoint. Path placeholders match by name; remaining entries become query string on GET/DELETE or JSON body on POST/PUT/PATCH.")),
		),
		handleCodeOrchExecute,
	)
}

// codeOrchEndpoint captures the small slice of endpoint metadata the
// search+execute pair needs at runtime. `keywords` is a precomputed
// lowercase stream of description + path tokens used for naive ranking;
// anything more sophisticated belongs on the agent side.
type codeOrchEndpoint struct {
	ID         string
	Method     string
	Path       string
	Tier       string
	Summary    string
	Positional []string
	keywords   []string
}

// codeOrchEndpoints is the generator-populated registry covering every
// endpoint declared in the spec. Kept flat on purpose — the agent queries
// via <api>_search, so hierarchy shows up as dotted IDs, not nested maps.
var codeOrchEndpoints = []codeOrchEndpoint{
	{
		ID:         "assets.create",
		Method:     "POST",
		Path:       "/assets/default/alerts/query",
		Summary:    "Get a list of Default Alerts.",
		Positional: []string{},
		keywords:   codeOrchKeywords("assets", "create", "Get a list of Default Alerts.", "/assets/default/alerts/query"),
	},
	{
		ID:         "assets.create-default",
		Method:     "POST",
		Path:       "/assets/default/maintenance/query",
		Summary:    "Get a list of Default Maintenance Jobs.",
		Positional: []string{},
		keywords:   codeOrchKeywords("assets", "create-default", "Get a list of Default Maintenance Jobs.", "/assets/default/maintenance/query"),
	},
	{
		ID:         "assets.create-default-2",
		Method:     "POST",
		Path:       "/assets/default/mdm-configurations/query",
		Summary:    "Get a list of Default MDM Configurations.",
		Positional: []string{},
		keywords:   codeOrchKeywords("assets", "create-default-2", "Get a list of Default MDM Configurations.", "/assets/default/mdm-configurations/query"),
	},
	{
		ID:         "assets.create-default-3",
		Method:     "POST",
		Path:       "/assets/default/self-service-configurations/query",
		Summary:    "Get a list of Default Self Service Configurations.",
		Positional: []string{},
		keywords:   codeOrchKeywords("assets", "create-default-3", "Get a list of Default Self Service Configurations.", "/assets/default/self-service-configurations/query"),
	},
	{
		ID:         "configuration.list",
		Method:     "GET",
		Path:       "/configuration/permissions",
		Summary:    "Get API key's permissions",
		Positional: []string{},
		keywords:   codeOrchKeywords("configuration", "list", "Get API key's permissions", "/configuration/permissions"),
	},
	{
		ID:         "device-script-assignments.create",
		Method:     "POST",
		Path:       "/device-script-assignments",
		Summary:    "Creates a device script assignment in the organization.",
		Positional: []string{},
		keywords:   codeOrchKeywords("device-script-assignments", "create", "Creates a device script assignment in the organization.", "/device-script-assignments"),
	},
	{
		ID:         "device-script-assignments.delete",
		Method:     "DELETE",
		Path:       "/device-script-assignments",
		Summary:    "Deletes a device script assignment from the organization.",
		Positional: []string{},
		keywords:   codeOrchKeywords("device-script-assignments", "delete", "Deletes a device script assignment from the organization.", "/device-script-assignments"),
	},
	{
		ID:         "device-script-assignments.list",
		Method:     "GET",
		Path:       "/device-script-assignments",
		Summary:    "Get Device Script Assignments available for the organization.",
		Positional: []string{},
		keywords:   codeOrchKeywords("device-script-assignments", "list", "Get Device Script Assignments available for the organization.", "/device-script-assignments"),
	},
	{
		ID:         "devices.create",
		Method:     "POST",
		Path:       "/devices",
		Summary:    "Allow to query for a set of devices based on a value that pertains to one of their device facts. <br><b>Permission...",
		Positional: []string{},
		keywords:   codeOrchKeywords("devices", "create", "Allow to query for a set of devices based on a value that pertains to one of their device facts. <br><b>Permission...", "/devices"),
	},
	{
		ID:         "facts.create",
		Method:     "POST",
		Path:       "/facts/custom",
		Summary:    "Create a custom fact.",
		Positional: []string{},
		keywords:   codeOrchKeywords("facts", "create", "Create a custom fact.", "/facts/custom"),
	},
	{
		ID:         "facts.create-custom",
		Method:     "POST",
		Path:       "/facts/custom/policy",
		Summary:    "Assign Custom Facts to policies.",
		Positional: []string{},
		keywords:   codeOrchKeywords("facts", "create-custom", "Assign Custom Facts to policies.", "/facts/custom/policy"),
	},
	{
		ID:         "facts.create-custom-2",
		Method:     "POST",
		Path:       "/facts/custom/query",
		Summary:    "Get a list of Custom Facts filtered by id or name for an organization.",
		Positional: []string{},
		keywords:   codeOrchKeywords("facts", "create-custom-2", "Get a list of Custom Facts filtered by id or name for an organization.", "/facts/custom/query"),
	},
	{
		ID:         "facts.delete",
		Method:     "DELETE",
		Path:       "/facts/custom",
		Summary:    "Delete a custom fact.",
		Positional: []string{},
		keywords:   codeOrchKeywords("facts", "delete", "Delete a custom fact.", "/facts/custom"),
	},
	{
		ID:         "facts.delete-custom",
		Method:     "DELETE",
		Path:       "/facts/custom/policy",
		Summary:    "Unassign a custom fact from a policy.",
		Positional: []string{},
		keywords:   codeOrchKeywords("facts", "delete-custom", "Unassign a custom fact from a policy.", "/facts/custom/policy"),
	},
	{
		ID:         "facts.list",
		Method:     "GET",
		Path:       "/facts/custom",
		Summary:    "Get all custom facts for the organization.",
		Positional: []string{},
		keywords:   codeOrchKeywords("facts", "list", "Get all custom facts for the organization.", "/facts/custom"),
	},
	{
		ID:         "facts.update",
		Method:     "PUT",
		Path:       "/facts/custom",
		Summary:    "Update a custom fact.",
		Positional: []string{},
		keywords:   codeOrchKeywords("facts", "update", "Update a custom fact.", "/facts/custom"),
	},
	{
		ID:         "feature-betas.create",
		Method:     "POST",
		Path:       "/feature-betas/organizations",
		Summary:    "Enables a Beta Feature in the organization. <br><b>Permission Required: </b>Toggle Feature Betas.",
		Positional: []string{},
		keywords:   codeOrchKeywords("feature-betas", "create", "Enables a Beta Feature in the organization. <br><b>Permission Required: </b>Toggle Feature Betas.", "/feature-betas/organizations"),
	},
	{
		ID:         "feature-betas.delete",
		Method:     "DELETE",
		Path:       "/feature-betas/organizations",
		Summary:    "Disables the Beta Features from the organization. <br><b>Permission Required: </b>Toggle Feature Betas.",
		Positional: []string{},
		keywords:   codeOrchKeywords("feature-betas", "delete", "Disables the Beta Features from the organization. <br><b>Permission Required: </b>Toggle Feature Betas.", "/feature-betas/organizations"),
	},
	{
		ID:         "feature-betas.list",
		Method:     "GET",
		Path:       "/feature-betas",
		Summary:    "Get all Beta Features available for the organization. <br><b>Permission Required: </b>Toggle Feature Betas.",
		Positional: []string{},
		keywords:   codeOrchKeywords("feature-betas", "list", "Get all Beta Features available for the organization. <br><b>Permission Required: </b>Toggle Feature Betas.", "/feature-betas"),
	},
	{
		ID:         "files.create",
		Method:     "POST",
		Path:       "/files/usage",
		Summary:    "Get a list of file usages for a list of File IDs.",
		Positional: []string{},
		keywords:   codeOrchKeywords("files", "create", "Get a list of file usages for a list of File IDs.", "/files/usage"),
	},
	{
		ID:         "maintenance.create",
		Method:     "POST",
		Path:       "/maintenance",
		Summary:    "Create a maintenance item. <br><b>Permission Required: </b>Create Catalog Maintenance.",
		Positional: []string{},
		keywords:   codeOrchKeywords("maintenance", "create", "Create a maintenance item. <br><b>Permission Required: </b>Create Catalog Maintenance.", "/maintenance"),
	},
	{
		ID:         "maintenance.create-policy",
		Method:     "POST",
		Path:       "/maintenance/policy",
		Summary:    "Assign polices to a maintenance item. <br><b>Permission Required: </b>Edit Policy Maintenance.",
		Positional: []string{},
		keywords:   codeOrchKeywords("maintenance", "create-policy", "Assign polices to a maintenance item. <br><b>Permission Required: </b>Edit Policy Maintenance.", "/maintenance/policy"),
	},
	{
		ID:         "maintenance.create-query",
		Method:     "POST",
		Path:       "/maintenance/query",
		Summary:    "Get a list of maintenance items for an organization.",
		Positional: []string{},
		keywords:   codeOrchKeywords("maintenance", "create-query", "Get a list of maintenance items for an organization.", "/maintenance/query"),
	},
	{
		ID:         "maintenance.create-staged",
		Method:     "POST",
		Path:       "/maintenance/staged",
		Summary:    "Creates a staged maintenance item from an existing one.",
		Positional: []string{},
		keywords:   codeOrchKeywords("maintenance", "create-staged", "Creates a staged maintenance item from an existing one.", "/maintenance/staged"),
	},
	{
		ID:         "maintenance.create-staged-2",
		Method:     "POST",
		Path:       "/maintenance/staged/confirm",
		Summary:    "Confirm a staged maintenance. This will create a maintenance with the same details as the staged maintenance and...",
		Positional: []string{},
		keywords:   codeOrchKeywords("maintenance", "create-staged-2", "Confirm a staged maintenance. This will create a maintenance with the same details as the staged maintenance and...", "/maintenance/staged/confirm"),
	},
	{
		ID:         "maintenance.create-staged-3",
		Method:     "POST",
		Path:       "/maintenance/staged/query",
		Summary:    "Get a list of maintenance items for an organization.",
		Positional: []string{},
		keywords:   codeOrchKeywords("maintenance", "create-staged-3", "Get a list of maintenance items for an organization.", "/maintenance/staged/query"),
	},
	{
		ID:         "maintenance.delete",
		Method:     "DELETE",
		Path:       "/maintenance",
		Summary:    "Delete a maintenance item.<br><b>Permission Required: </b>Delete Catalog Maintenance.",
		Positional: []string{},
		keywords:   codeOrchKeywords("maintenance", "delete", "Delete a maintenance item.<br><b>Permission Required: </b>Delete Catalog Maintenance.", "/maintenance"),
	},
	{
		ID:         "maintenance.delete-policy",
		Method:     "DELETE",
		Path:       "/maintenance/policy",
		Summary:    "Unassign a maintenance item from policy. <br><b>Permission Required: </b>Edit Policy Maintenance.",
		Positional: []string{},
		keywords:   codeOrchKeywords("maintenance", "delete-policy", "Unassign a maintenance item from policy. <br><b>Permission Required: </b>Edit Policy Maintenance.", "/maintenance/policy"),
	},
	{
		ID:         "maintenance.delete-staged",
		Method:     "DELETE",
		Path:       "/maintenance/staged",
		Summary:    "Deletes a staged maintenance item.",
		Positional: []string{},
		keywords:   codeOrchKeywords("maintenance", "delete-staged", "Deletes a staged maintenance item.", "/maintenance/staged"),
	},
	{
		ID:         "maintenance.update",
		Method:     "PUT",
		Path:       "/maintenance",
		Summary:    "Update a maintenance item. <br><b>Permission Required: </b>Edit Catalog Maintenance.",
		Positional: []string{},
		keywords:   codeOrchKeywords("maintenance", "update", "Update a maintenance item. <br><b>Permission Required: </b>Edit Catalog Maintenance.", "/maintenance"),
	},
	{
		ID:         "maintenance.update-staged",
		Method:     "PUT",
		Path:       "/maintenance/staged",
		Summary:    "Updates a staged maintenance item.",
		Positional: []string{},
		keywords:   codeOrchKeywords("maintenance", "update-staged", "Updates a staged maintenance item.", "/maintenance/staged"),
	},
	{
		ID:         "managed-app-configurations.create",
		Method:     "POST",
		Path:       "/managed-app-configurations",
		Summary:    "Requests to create managed app configuration for Apps & Books applications.",
		Positional: []string{},
		keywords:   codeOrchKeywords("managed-app-configurations", "create", "Requests to create managed app configuration for Apps & Books applications.", "/managed-app-configurations"),
	},
	{
		ID:         "managed-app-configurations.delete",
		Method:     "DELETE",
		Path:       "/managed-app-configurations",
		Summary:    "Requests to delete managed app configuration for Apps & Books applications.",
		Positional: []string{},
		keywords:   codeOrchKeywords("managed-app-configurations", "delete", "Requests to delete managed app configuration for Apps & Books applications.", "/managed-app-configurations"),
	},
	{
		ID:         "managed-app-configurations.list",
		Method:     "GET",
		Path:       "/managed-app-configurations",
		Summary:    "Gets managed app configuration for Apps & Books applications.",
		Positional: []string{},
		keywords:   codeOrchKeywords("managed-app-configurations", "list", "Gets managed app configuration for Apps & Books applications.", "/managed-app-configurations"),
	},
	{
		ID:         "mdm.create",
		Method:     "POST",
		Path:       "/mdm/certificates/query",
		Summary:    "Paginated request that returns list of installed certificates by mdm devices. <br><br><b>Permission Required:...",
		Positional: []string{},
		keywords:   codeOrchKeywords("mdm", "create", "Paginated request that returns list of installed certificates by mdm devices. <br><br><b>Permission Required:...", "/mdm/certificates/query"),
	},
	{
		ID:         "mdm.create-commands",
		Method:     "POST",
		Path:       "/mdm/commands/device/restart",
		Summary:    "Send MDM command to restart a device",
		Positional: []string{},
		keywords:   codeOrchKeywords("mdm", "create-commands", "Send MDM command to restart a device", "/mdm/commands/device/restart"),
	},
	{
		ID:         "mdm.create-configurations",
		Method:     "POST",
		Path:       "/mdm/configurations/profile",
		Summary:    "Create MDM configuration profile",
		Positional: []string{},
		keywords:   codeOrchKeywords("mdm", "create-configurations", "Create MDM configuration profile", "/mdm/configurations/profile"),
	},
	{
		ID:         "mdm.create-configurations-2",
		Method:     "POST",
		Path:       "/mdm/configurations/profile/policies",
		Summary:    "Assign policies to manifest-based MDM configuration profile",
		Positional: []string{},
		keywords:   codeOrchKeywords("mdm", "create-configurations-2", "Assign policies to manifest-based MDM configuration profile", "/mdm/configurations/profile/policies"),
	},
	{
		ID:         "mdm.create-configurations-3",
		Method:     "POST",
		Path:       "/mdm/configurations/profiles/stage",
		Summary:    "Confirm changes to manifest-based MDM configuration profile",
		Positional: []string{},
		keywords:   codeOrchKeywords("mdm", "create-configurations-3", "Confirm changes to manifest-based MDM configuration profile", "/mdm/configurations/profiles/stage"),
	},
	{
		ID:         "mdm.create-devices",
		Method:     "POST",
		Path:       "/mdm/devices/profile/deploy",
		Summary:    "Deploys profile to list of devices and/or managed users. It is an atomic request meaning that if one error is...",
		Positional: []string{},
		keywords:   codeOrchKeywords("mdm", "create-devices", "Deploys profile to list of devices and/or managed users. It is an atomic request meaning that if one error is...", "/mdm/devices/profile/deploy"),
	},
	{
		ID:         "mdm.create-profiles",
		Method:     "POST",
		Path:       "/mdm/profiles/policies",
		Summary:    "Get MDM profiles assigned to policies",
		Positional: []string{},
		keywords:   codeOrchKeywords("mdm", "create-profiles", "Get MDM profiles assigned to policies", "/mdm/profiles/policies"),
	},
	{
		ID:         "mdm.delete",
		Method:     "DELETE",
		Path:       "/mdm/commands/device-user",
		Summary:    "This command allows the server to delete a user that has an active account on the device. Please provide the device...",
		Positional: []string{},
		keywords:   codeOrchKeywords("mdm", "delete", "This command allows the server to delete a user that has an active account on the device. Please provide the device...", "/mdm/commands/device-user"),
	},
	{
		ID:         "mdm.delete-configurations",
		Method:     "DELETE",
		Path:       "/mdm/configurations/profile/policies",
		Summary:    "Unassign an MDM profile from policies",
		Positional: []string{},
		keywords:   codeOrchKeywords("mdm", "delete-configurations", "Unassign an MDM profile from policies", "/mdm/configurations/profile/policies"),
	},
	{
		ID:         "mdm.delete-configurations-2",
		Method:     "DELETE",
		Path:       "/mdm/configurations/profile/{payload_group_id}",
		Summary:    "Delete manifest-based MDM configuration profile",
		Positional: []string{"payload_group_id"},
		keywords:   codeOrchKeywords("mdm", "delete-configurations-2", "Delete manifest-based MDM configuration profile", "/mdm/configurations/profile/{payload_group_id}"),
	},
	{
		ID:         "mdm.get",
		Method:     "GET",
		Path:       "/mdm/devices/{device_uuid}",
		Summary:    "Get MDM device details including enrollment profile, APN certificate and last response.",
		Positional: []string{"device_uuid"},
		keywords:   codeOrchKeywords("mdm", "get", "Get MDM device details including enrollment profile, APN certificate and last response.", "/mdm/devices/{device_uuid}"),
	},
	{
		ID:         "mdm.get-configurations",
		Method:     "GET",
		Path:       "/mdm/configurations/definition/{addigy_payload_type}",
		Summary:    "Get MDM configuration profile definition",
		Positional: []string{"addigy_payload_type"},
		keywords:   codeOrchKeywords("mdm", "get-configurations", "Get MDM configuration profile definition", "/mdm/configurations/definition/{addigy_payload_type}"),
	},
	{
		ID:         "mdm.get-configurations-2",
		Method:     "GET",
		Path:       "/mdm/configurations/profile/{payload_group_id}",
		Summary:    "Get manifest-based MDM configuration profile",
		Positional: []string{"payload_group_id"},
		keywords:   codeOrchKeywords("mdm", "get-configurations-2", "Get manifest-based MDM configuration profile", "/mdm/configurations/profile/{payload_group_id}"),
	},
	{
		ID:         "mdm.get-devices",
		Method:     "GET",
		Path:       "/mdm/devices/{device_uuid}/test",
		Summary:    "Test MDM response.",
		Positional: []string{"device_uuid"},
		keywords:   codeOrchKeywords("mdm", "get-devices", "Test MDM response.", "/mdm/devices/{device_uuid}/test"),
	},
	{
		ID:         "mdm.list",
		Method:     "GET",
		Path:       "/mdm/profiles",
		Summary:    "Get MDM profiles",
		Positional: []string{},
		keywords:   codeOrchKeywords("mdm", "list", "Get MDM profiles", "/mdm/profiles"),
	},
	{
		ID:         "mdm.list-commands",
		Method:     "GET",
		Path:       "/mdm/commands/device-users/query",
		Summary:    "Returns a list of known users that were given to Addigy via the Request User List command.Please provide the device...",
		Positional: []string{},
		keywords:   codeOrchKeywords("mdm", "list-commands", "Returns a list of known users that were given to Addigy via the Request User List command.Please provide the device...", "/mdm/commands/device-users/query"),
	},
	{
		ID:         "mdm.list-configurations",
		Method:     "GET",
		Path:       "/mdm/configurations/definitions",
		Summary:    "Get MDM configuration profile definitions",
		Positional: []string{},
		keywords:   codeOrchKeywords("mdm", "list-configurations", "Get MDM configuration profile definitions", "/mdm/configurations/definitions"),
	},
	{
		ID:         "mdm.list-configurations-2",
		Method:     "GET",
		Path:       "/mdm/configurations/profiles",
		Summary:    "Get manifest-based MDM configuration profiles",
		Positional: []string{},
		keywords:   codeOrchKeywords("mdm", "list-configurations-2", "Get manifest-based MDM configuration profiles", "/mdm/configurations/profiles"),
	},
	{
		ID:         "mdm.list-configurations-3",
		Method:     "GET",
		Path:       "/mdm/configurations/policy/profiles",
		Summary:    "Get policy profiles by Addigy payload type",
		Positional: []string{},
		keywords:   codeOrchKeywords("mdm", "list-configurations-3", "Get policy profiles by Addigy payload type", "/mdm/configurations/policy/profiles"),
	},
	{
		ID:         "mdm.update",
		Method:     "PUT",
		Path:       "/mdm/configurations/profiles/stage",
		Summary:    "Update an MDM configuration profile",
		Positional: []string{},
		keywords:   codeOrchKeywords("mdm", "update", "Update an MDM configuration profile", "/mdm/configurations/profiles/stage"),
	},
	{
		ID:         "monitoring.create",
		Method:     "POST",
		Path:       "/monitoring",
		Summary:    "Create a monitoring item.",
		Positional: []string{},
		keywords:   codeOrchKeywords("monitoring", "create", "Create a monitoring item.", "/monitoring"),
	},
	{
		ID:         "monitoring.create-policy",
		Method:     "POST",
		Path:       "/monitoring/policy",
		Summary:    "Assign monitoring item to policy. <br><b>Permission Required: </b>Edit Policy Monitoring.",
		Positional: []string{},
		keywords:   codeOrchKeywords("monitoring", "create-policy", "Assign monitoring item to policy. <br><b>Permission Required: </b>Edit Policy Monitoring.", "/monitoring/policy"),
	},
	{
		ID:         "monitoring.create-query",
		Method:     "POST",
		Path:       "/monitoring/query",
		Summary:    "Get a list of monitoring items for an organization.",
		Positional: []string{},
		keywords:   codeOrchKeywords("monitoring", "create-query", "Get a list of monitoring items for an organization.", "/monitoring/query"),
	},
	{
		ID:         "monitoring.delete",
		Method:     "DELETE",
		Path:       "/monitoring",
		Summary:    "Delete a monitoring item.<br><b>Permission Required: </b>Delete Custom Monitoring.",
		Positional: []string{},
		keywords:   codeOrchKeywords("monitoring", "delete", "Delete a monitoring item.<br><b>Permission Required: </b>Delete Custom Monitoring.", "/monitoring"),
	},
	{
		ID:         "monitoring.delete-policy",
		Method:     "DELETE",
		Path:       "/monitoring/policy",
		Summary:    "Unassign a monitoring item from policy. <br><b>Permission Required: </b>Edit Policy Monitoring.",
		Positional: []string{},
		keywords:   codeOrchKeywords("monitoring", "delete-policy", "Unassign a monitoring item from policy. <br><b>Permission Required: </b>Edit Policy Monitoring.", "/monitoring/policy"),
	},
	{
		ID:         "monitoring.list",
		Method:     "GET",
		Path:       "/monitoring/received-alerts",
		Summary:    "Get list of received alerts for the organization.",
		Positional: []string{},
		keywords:   codeOrchKeywords("monitoring", "list", "Get list of received alerts for the organization.", "/monitoring/received-alerts"),
	},
	{
		ID:         "monitoring.update",
		Method:     "PUT",
		Path:       "/monitoring",
		Summary:    "Update a monitoring item.",
		Positional: []string{},
		keywords:   codeOrchKeywords("monitoring", "update", "Update a monitoring item.", "/monitoring"),
	},
	{
		ID:         "o.create",
		Method:     "POST",
		Path:       "/o/integrations/azure-ca/tenants/expand-request",
		Summary:    "Request additional Azure Conditional Access Connectors for their organization.",
		Positional: []string{},
		keywords:   codeOrchKeywords("o", "create", "Request additional Azure Conditional Access Connectors for their organization.", "/o/integrations/azure-ca/tenants/expand-request"),
	},
	{
		ID:         "o.benchmarks.create",
		Method:     "POST",
		Path:       "/o/{organization_id}/benchmarks",
		Summary:    "Create a benchmark asset. <br><b>Permission Required: </b>Create Benchmark.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "create", "Create a benchmark asset. <br><b>Permission Required: </b>Create Benchmark.", "/o/{organization_id}/benchmarks"),
	},
	{
		ID:         "o.benchmarks.create-o",
		Method:     "POST",
		Path:       "/o/{organization_id}/benchmarks/pre-built/clone",
		Summary:    "Clone a pre built benchmark. <br><b>Permission Required: </b>Create Benchmark.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "create-o", "Clone a pre built benchmark. <br><b>Permission Required: </b>Create Benchmark.", "/o/{organization_id}/benchmarks/pre-built/clone"),
	},
	{
		ID:         "o.benchmarks.delete",
		Method:     "DELETE",
		Path:       "/o/{organization_id}/benchmarks",
		Summary:    "Delete a benchmark asset.<br><b>Permission Required: </b>Delete Benchmark.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "delete", "Delete a benchmark asset.<br><b>Permission Required: </b>Delete Benchmark.", "/o/{organization_id}/benchmarks"),
	},
	{
		ID:         "o.benchmarks.update",
		Method:     "PUT",
		Path:       "/o/{organization_id}/benchmarks",
		Summary:    "Update a benchmark asset. <br><b>Permission Required: </b>Edit Benchmark.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "update", "Update a benchmark asset. <br><b>Permission Required: </b>Edit Benchmark.", "/o/{organization_id}/benchmarks"),
	},
	{
		ID:         "o.children.get",
		Method:     "GET",
		Path:       "/o/{organization_id}/children/query",
		Summary:    "Get a list of child organizations belonging to the provided organization",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "get", "Get a list of child organizations belonging to the provided organization", "/o/{organization_id}/children/query"),
	},
	{
		ID:         "o.community.create",
		Method:     "POST",
		Path:       "/o/{organization_id}/community/report",
		Summary:    "Report a community fact or command to Addigy for review.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "create", "Report a community fact or command to Addigy for review.", "/o/{organization_id}/community/report"),
	},
	{
		ID:         "o.compliance-rules.create",
		Method:     "POST",
		Path:       "/o/{organization_id}/compliance-rules",
		Summary:    "Create a compliance rule. <br><b>Permission Required: </b>Create Benchmark.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "create", "Create a compliance rule. <br><b>Permission Required: </b>Create Benchmark.", "/o/{organization_id}/compliance-rules"),
	},
	{
		ID:         "o.compliance-rules.delete",
		Method:     "DELETE",
		Path:       "/o/{organization_id}/compliance-rules",
		Summary:    "Delete a compliance rule.<br><b>Permission Required: </b>Delete Benchmark.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "delete", "Delete a compliance rule.<br><b>Permission Required: </b>Delete Benchmark.", "/o/{organization_id}/compliance-rules"),
	},
	{
		ID:         "o.compliance-rules.get",
		Method:     "GET",
		Path:       "/o/{organization_id}/compliance-rules/scripts",
		Summary:    "Get compliance rules using script. <br><b>Permission Required: </b>View Benchmarks.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "get", "Get compliance rules using script. <br><b>Permission Required: </b>View Benchmarks.", "/o/{organization_id}/compliance-rules/scripts"),
	},
	{
		ID:         "o.compliance-rules.update",
		Method:     "PUT",
		Path:       "/o/{organization_id}/compliance-rules",
		Summary:    "Update a compliance rule. <br><b>Permission Required: </b>Edit Benchmark.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "update", "Update a compliance rule. <br><b>Permission Required: </b>Edit Benchmark.", "/o/{organization_id}/compliance-rules"),
	},
	{
		ID:         "o.ddm-updates.get",
		Method:     "GET",
		Path:       "/o/{organization_id}/ddm-updates/devices/declarations/active",
		Summary:    "Gets device active ddm system updates declaration.<br><b>Permission Required: </b>View devices.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "get", "Gets device active ddm system updates declaration.<br><b>Permission Required: </b>View devices.", "/o/{organization_id}/ddm-updates/devices/declarations/active"),
	},
	{
		ID:         "o.device.get",
		Method:     "GET",
		Path:       "/o/{organization_id}/device/compliance/benchmark/status",
		Summary:    "Get device compliance statuses per benchmark.<br><b>Permission Required: </b>View devices.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "get", "Get device compliance statuses per benchmark.<br><b>Permission Required: </b>View devices.", "/o/{organization_id}/device/compliance/benchmark/status"),
	},
	{
		ID:         "o.devices.create",
		Method:     "POST",
		Path:       "/o/{organization_id}/devices/filters/prompt",
		Summary:    "Get list of device filters based on users text prompt explaining what they need.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "create", "Get list of device filters based on users text prompt explaining what they need.", "/o/{organization_id}/devices/filters/prompt"),
	},
	{
		ID:         "o.homescreen.create",
		Method:     "POST",
		Path:       "/o/{organization_id}/homescreen",
		Summary:    "Create a policy home screen layout",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "create", "Create a policy home screen layout", "/o/{organization_id}/homescreen"),
	},
	{
		ID:         "o.homescreen.create-o",
		Method:     "POST",
		Path:       "/o/{organization_id}/homescreen/assigned",
		Summary:    "Set the policy assignment status for a home screen layout",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "create-o", "Set the policy assignment status for a home screen layout", "/o/{organization_id}/homescreen/assigned"),
	},
	{
		ID:         "o.homescreen.delete",
		Method:     "DELETE",
		Path:       "/o/{organization_id}/homescreen",
		Summary:    "Delete a policy home screen layout",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "delete", "Delete a policy home screen layout", "/o/{organization_id}/homescreen"),
	},
	{
		ID:         "o.identity.update",
		Method:     "PUT",
		Path:       "/o/{organization_id}/identity/configurations/policies",
		Summary:    "Stores an identity configuration assigned to a policy.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "update", "Stores an identity configuration assigned to a policy.", "/o/{organization_id}/identity/configurations/policies"),
	},
	{
		ID:         "o.integrations.create",
		Method:     "POST",
		Path:       "/o/{organization_id}/integrations/mbov",
		Summary:    "Enable MalwareBytes OneView integration. Create new account. <br><b>Permission Required: </b>Create Integration.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "create", "Enable MalwareBytes OneView integration. Create new account. <br><b>Permission Required: </b>Create Integration.", "/o/{organization_id}/integrations/mbov"),
	},
	{
		ID:         "o.integrations.create-o",
		Method:     "POST",
		Path:       "/o/{organization_id}/integrations/mbov/sync",
		Summary:    "Enable MalwareBytes OneView integration. Sync with an existing account. <br><b>Permission Required: </b>Create...",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "create-o", "Enable MalwareBytes OneView integration. Sync with an existing account. <br><b>Permission Required: </b>Create...", "/o/{organization_id}/integrations/mbov/sync"),
	},
	{
		ID:         "o.integrations.create-o-2",
		Method:     "POST",
		Path:       "/o/{organization_id}/integrations/autotask/policy/device/sync",
		Summary:    "Sync policy devices with Autotask configurations. <br><b>Permission Required: </b>Edit Integration.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "create-o-2", "Sync policy devices with Autotask configurations. <br><b>Permission Required: </b>Edit Integration.", "/o/{organization_id}/integrations/autotask/policy/device/sync"),
	},
	{
		ID:         "o.integrations.create-o-3",
		Method:     "POST",
		Path:       "/o/{organization_id}/integrations/connectwise/policy/device/sync",
		Summary:    "Sync policy devices with ConnectWise configurations. <br><b>Permission Required: </b>Edit Integration.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "create-o-3", "Sync policy devices with ConnectWise configurations. <br><b>Permission Required: </b>Edit Integration.", "/o/{organization_id}/integrations/connectwise/policy/device/sync"),
	},
	{
		ID:         "o.integrations.delete",
		Method:     "DELETE",
		Path:       "/o/{organization_id}/integrations/mbov",
		Summary:    "Enable MalwareBytes OneView integration.<br><b>Permission Required: </b>Delete Integration.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "delete", "Enable MalwareBytes OneView integration.<br><b>Permission Required: </b>Delete Integration.", "/o/{organization_id}/integrations/mbov"),
	},
	{
		ID:         "o.integrations.get",
		Method:     "GET",
		Path:       "/o/{organization_id}/integrations/mbov/sites",
		Summary:    "Get MalwareBytes OneView sites for the organization.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "get", "Get MalwareBytes OneView sites for the organization.", "/o/{organization_id}/integrations/mbov/sites"),
	},
	{
		ID:         "o.integrations.get-o",
		Method:     "GET",
		Path:       "/o/{organization_id}/integrations/mbov/account/status",
		Summary:    "Get MalwareBytes OneView account status.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "get-o", "Get MalwareBytes OneView account status.", "/o/{organization_id}/integrations/mbov/account/status"),
	},
	{
		ID:         "o.integrations.get-o-2",
		Method:     "GET",
		Path:       "/o/{organization_id}/integrations/mbov/account/usage",
		Summary:    "Get MalwareBytes OneView account catalog usage. <br><b>Permission Required: </b>Enable Integration. Install MBBR'",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "get-o-2", "Get MalwareBytes OneView account catalog usage. <br><b>Permission Required: </b>Enable Integration. Install MBBR'", "/o/{organization_id}/integrations/mbov/account/usage"),
	},
	{
		ID:         "o.mdm.create",
		Method:     "POST",
		Path:       "/o/{organization_id}/mdm/payloads/query",
		Summary:    "Query MDM Payload information and assignments",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "create", "Query MDM Payload information and assignments", "/o/{organization_id}/mdm/payloads/query"),
	},
	{
		ID:         "o.mdm.create-o",
		Method:     "POST",
		Path:       "/o/{organization_id}/mdm/enrollment/profile/install",
		Summary:    "Install MDM enrollment profile via mdm if available or via agent for macOS devices",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "create-o", "Install MDM enrollment profile via mdm if available or via agent for macOS devices", "/o/{organization_id}/mdm/enrollment/profile/install"),
	},
	{
		ID:         "o.monitoring.create",
		Method:     "POST",
		Path:       "/o/{organization_id}/monitoring/stage",
		Summary:    "Create a staged alert",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "create", "Create a staged alert", "/o/{organization_id}/monitoring/stage"),
	},
	{
		ID:         "o.monitoring.create-o",
		Method:     "POST",
		Path:       "/o/{organization_id}/monitoring/stage/confirm",
		Summary:    "Confirm a staged alert. Copies changes into actual alert.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "create-o", "Confirm a staged alert. Copies changes into actual alert.", "/o/{organization_id}/monitoring/stage/confirm"),
	},
	{
		ID:         "o.monitoring.delete",
		Method:     "DELETE",
		Path:       "/o/{organization_id}/monitoring/stage",
		Summary:    "Delete a staged alert",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "delete", "Delete a staged alert", "/o/{organization_id}/monitoring/stage"),
	},
	{
		ID:         "o.monitoring.update",
		Method:     "PUT",
		Path:       "/o/{organization_id}/monitoring/stage",
		Summary:    "Update a staged alert",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "update", "Update a staged alert", "/o/{organization_id}/monitoring/stage"),
	},
	{
		ID:         "o.policies.create",
		Method:     "POST",
		Path:       "/o/{organization_id}/policies",
		Summary:    "Create a policy. <br><b>Permission Required: </b>Create Policy.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "create", "Create a policy. <br><b>Permission Required: </b>Create Policy.", "/o/{organization_id}/policies"),
	},
	{
		ID:         "o.policies.create-o",
		Method:     "POST",
		Path:       "/o/{organization_id}/policies/rule",
		Summary:    "Add assignment rule to policy. <br><b>Permission Required: </b>Automatic Policy Assignments.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "create-o", "Add assignment rule to policy. <br><b>Permission Required: </b>Automatic Policy Assignments.", "/o/{organization_id}/policies/rule"),
	},
	{
		ID:         "o.policies.delete",
		Method:     "DELETE",
		Path:       "/o/{organization_id}/policies",
		Summary:    "Delete a policy. <br><b>Permission Required: </b>Delete Policy.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "delete", "Delete a policy. <br><b>Permission Required: </b>Delete Policy.", "/o/{organization_id}/policies"),
	},
	{
		ID:         "o.policies.delete-o",
		Method:     "DELETE",
		Path:       "/o/{organization_id}/policies/parent",
		Summary:    "Delete a policy parent. <br><b>Permission Required: </b>Edit Policy.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "delete-o", "Delete a policy parent. <br><b>Permission Required: </b>Edit Policy.", "/o/{organization_id}/policies/parent"),
	},
	{
		ID:         "o.policies.delete-o-2",
		Method:     "DELETE",
		Path:       "/o/{organization_id}/policies/rule",
		Summary:    "Remove assignment rule from policy. <br><b>Permission Required: </b>Automatic Policy Assignments.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "delete-o-2", "Remove assignment rule from policy. <br><b>Permission Required: </b>Automatic Policy Assignments.", "/o/{organization_id}/policies/rule"),
	},
	{
		ID:         "o.policies.get",
		Method:     "GET",
		Path:       "/o/{organization_id}/policies/rule",
		Summary:    "Get policy assignment rules. <br><b>Permission Required: </b>.Automatic Policy Assignments",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "get", "Get policy assignment rules. <br><b>Permission Required: </b>.Automatic Policy Assignments", "/o/{organization_id}/policies/rule"),
	},
	{
		ID:         "o.policies.update",
		Method:     "PUT",
		Path:       "/o/{organization_id}/policies",
		Summary:    "Update a policy. <br><b>Permission Required: </b>Edit Policy.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "update", "Update a policy. <br><b>Permission Required: </b>Edit Policy.", "/o/{organization_id}/policies"),
	},
	{
		ID:         "o.policies.update-o",
		Method:     "PUT",
		Path:       "/o/{organization_id}/policies/parent",
		Summary:    "Update a policy parent. <br><b>Permission Required: </b>Edit Policy.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "update-o", "Update a policy parent. <br><b>Permission Required: </b>Edit Policy.", "/o/{organization_id}/policies/parent"),
	},
	{
		ID:         "o.policy.create",
		Method:     "POST",
		Path:       "/o/{organization_id}/policy/mbov-sites",
		Summary:    "Assign a MalwareBytes OneView site to a policy. <br><b>Permission Required: </b>Edit Policy.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "create", "Assign a MalwareBytes OneView site to a policy. <br><b>Permission Required: </b>Edit Policy.", "/o/{organization_id}/policy/mbov-sites"),
	},
	{
		ID:         "o.policy.create-o",
		Method:     "POST",
		Path:       "/o/{organization_id}/policy/assets/benchmarks",
		Summary:    "Assign a benchmark to a policy. <br><b>Permission Required: </b>Edit Policy Benchmarks.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "create-o", "Assign a benchmark to a policy. <br><b>Permission Required: </b>Edit Policy Benchmarks.", "/o/{organization_id}/policy/assets/benchmarks"),
	},
	{
		ID:         "o.policy.delete",
		Method:     "DELETE",
		Path:       "/o/{organization_id}/policy/mbov-sites",
		Summary:    "Remove a MalwareBytes OneView site from a policy. <br><b>Permission Required: </b>Edit Policy.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "delete", "Remove a MalwareBytes OneView site from a policy. <br><b>Permission Required: </b>Edit Policy.", "/o/{organization_id}/policy/mbov-sites"),
	},
	{
		ID:         "o.policy.delete-o",
		Method:     "DELETE",
		Path:       "/o/{organization_id}/policy/assets/benchmarks",
		Summary:    "Remove a benchmark from a policy. <br><b>Permission Required: </b>Edit Policy Benchmarks.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "delete-o", "Remove a benchmark from a policy. <br><b>Permission Required: </b>Edit Policy Benchmarks.", "/o/{organization_id}/policy/assets/benchmarks"),
	},
	{
		ID:         "o.policy.get",
		Method:     "GET",
		Path:       "/o/{organization_id}/policy/mbov-sites",
		Summary:    "Get MalwareBytes OneView policy sites. <br><b>Permission Required: </b>Edit Policy.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "get", "Get MalwareBytes OneView policy sites. <br><b>Permission Required: </b>Edit Policy.", "/o/{organization_id}/policy/mbov-sites"),
	},
	{
		ID:         "o.prebuilt-apps.create",
		Method:     "POST",
		Path:       "/o/{organization_id}/prebuilt-apps/configurations",
		Summary:    "Create a prebuilt app configuration and assign it to one or more policies",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "create", "Create a prebuilt app configuration and assign it to one or more policies", "/o/{organization_id}/prebuilt-apps/configurations"),
	},
	{
		ID:         "o.prebuilt-apps.delete",
		Method:     "DELETE",
		Path:       "/o/{organization_id}/prebuilt-apps/configurations/{id}",
		Summary:    "Delete a prebuilt app configuration, removing it from all assigned policies",
		Positional: []string{"organization_id", "id"},
		keywords:   codeOrchKeywords("o", "delete", "Delete a prebuilt app configuration, removing it from all assigned policies", "/o/{organization_id}/prebuilt-apps/configurations/{id}"),
	},
	{
		ID:         "o.prebuilt-apps.delete-o",
		Method:     "DELETE",
		Path:       "/o/{organization_id}/prebuilt-apps/configurations/{id}/assignment",
		Summary:    "Unassign a configuration from one or more policies. The configuration must belong to at least one policy.",
		Positional: []string{"organization_id", "id"},
		keywords:   codeOrchKeywords("o", "delete-o", "Unassign a configuration from one or more policies. The configuration must belong to at least one policy.", "/o/{organization_id}/prebuilt-apps/configurations/{id}/assignment"),
	},
	{
		ID:         "o.prebuilt-apps.update",
		Method:     "PUT",
		Path:       "/o/{organization_id}/prebuilt-apps/configurations/{id}",
		Summary:    "Update a prebuilt app configuration",
		Positional: []string{"organization_id", "id"},
		keywords:   codeOrchKeywords("o", "update", "Update a prebuilt app configuration", "/o/{organization_id}/prebuilt-apps/configurations/{id}"),
	},
	{
		ID:         "o.prebuilt-apps.update-o",
		Method:     "PUT",
		Path:       "/o/{organization_id}/prebuilt-apps/configurations/{id}/assignment",
		Summary:    "Assign a configuration to one or more policies",
		Positional: []string{"organization_id", "id"},
		keywords:   codeOrchKeywords("o", "update-o", "Assign a configuration to one or more policies", "/o/{organization_id}/prebuilt-apps/configurations/{id}/assignment"),
	},
	{
		ID:         "o.reports.create",
		Method:     "POST",
		Path:       "/o/{organization_id}/reports",
		Summary:    "Request a report. Only one report of each type can be requested at a time.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "create", "Request a report. Only one report of each type can be requested at a time.", "/o/{organization_id}/reports"),
	},
	{
		ID:         "o.scripts.delete",
		Method:     "DELETE",
		Path:       "/o/{organization_id}/scripts",
		Summary:    "Delete a script. <br><b>Permission Required: </b>Delete Predefined Commands.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "delete", "Delete a script. <br><b>Permission Required: </b>Delete Predefined Commands.", "/o/{organization_id}/scripts"),
	},
	{
		ID:         "o.templates.create",
		Method:     "POST",
		Path:       "/o/{organization_id}/templates",
		Summary:    "Create a policy with the assets associated to a template. <br><b>Permission Required: </b>Create Policy.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "create", "Create a policy with the assets associated to a template. <br><b>Permission Required: </b>Create Policy.", "/o/{organization_id}/templates"),
	},
	{
		ID:         "o.templates.create-o",
		Method:     "POST",
		Path:       "/o/{organization_id}/templates/query",
		Summary:    "Get a list of Templates.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "create-o", "Get a list of Templates.", "/o/{organization_id}/templates/query"),
	},
	{
		ID:         "o.users.create",
		Method:     "POST",
		Path:       "/o/{organization_id}/users/query",
		Summary:    "Query for organization users.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "create", "Query for organization users.", "/o/{organization_id}/users/query"),
	},
	{
		ID:         "o.variables.create",
		Method:     "POST",
		Path:       "/o/{organization_id}/variables",
		Summary:    "Create a variable. <br><b>Permission Required: </b>Create Variable.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "create", "Create a variable. <br><b>Permission Required: </b>Create Variable.", "/o/{organization_id}/variables"),
	},
	{
		ID:         "o.variables.create-o",
		Method:     "POST",
		Path:       "/o/{organization_id}/variables/policies",
		Summary:    "Assign policy value to a variable. <br><b>Permission Required: </b>Edit Policy.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "create-o", "Assign policy value to a variable. <br><b>Permission Required: </b>Edit Policy.", "/o/{organization_id}/variables/policies"),
	},
	{
		ID:         "o.variables.delete",
		Method:     "DELETE",
		Path:       "/o/{organization_id}/variables",
		Summary:    "Delete a variable.<br><b>Permission Required: </b>Delete Variable.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "delete", "Delete a variable.<br><b>Permission Required: </b>Delete Variable.", "/o/{organization_id}/variables"),
	},
	{
		ID:         "o.variables.delete-o",
		Method:     "DELETE",
		Path:       "/o/{organization_id}/variables/policies",
		Summary:    "Remove policy value from a variable. <br><b>Permission Required: </b>Edit Policy.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "delete-o", "Remove policy value from a variable. <br><b>Permission Required: </b>Edit Policy.", "/o/{organization_id}/variables/policies"),
	},
	{
		ID:         "o.variables.get",
		Method:     "GET",
		Path:       "/o/{organization_id}/variables/policies",
		Summary:    "Get policy variable value. <br><b>Permission Required: </b>Edit Policy.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "get", "Get policy variable value. <br><b>Permission Required: </b>Edit Policy.", "/o/{organization_id}/variables/policies"),
	},
	{
		ID:         "o.variables.get-o",
		Method:     "GET",
		Path:       "/o/{organization_id}/variables/usage",
		Summary:    "Get variable usage.<br><b>Permission Required: </b>View Variable.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "get-o", "Get variable usage.<br><b>Permission Required: </b>View Variable.", "/o/{organization_id}/variables/usage"),
	},
	{
		ID:         "o.variables.get-o-2",
		Method:     "GET",
		Path:       "/o/{organization_id}/variables/value",
		Summary:    "Get variable value.<br><b>Permission Required: </b>View Variable.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "get-o-2", "Get variable value.<br><b>Permission Required: </b>View Variable.", "/o/{organization_id}/variables/value"),
	},
	{
		ID:         "o.variables.get-o-3",
		Method:     "GET",
		Path:       "/o/{organization_id}/variables/policies/value",
		Summary:    "Get variable policy value.<br><b>Permission Required: </b>View Variable.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "get-o-3", "Get variable policy value.<br><b>Permission Required: </b>View Variable.", "/o/{organization_id}/variables/policies/value"),
	},
	{
		ID:         "o.variables.update",
		Method:     "PUT",
		Path:       "/o/{organization_id}/variables",
		Summary:    "Update a variable. <br><b>Permission Required: </b>Edit Variable.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "update", "Update a variable. <br><b>Permission Required: </b>Edit Variable.", "/o/{organization_id}/variables"),
	},
	{
		ID:         "o.webhooks.create",
		Method:     "POST",
		Path:       "/o/{organization_id}/webhooks",
		Summary:    "Create a webhook.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "create", "Create a webhook.", "/o/{organization_id}/webhooks"),
	},
	{
		ID:         "o.webhooks.delete",
		Method:     "DELETE",
		Path:       "/o/{organization_id}/webhooks",
		Summary:    "Delete a webhook.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "delete", "Delete a webhook.", "/o/{organization_id}/webhooks"),
	},
	{
		ID:         "o.webhooks.update",
		Method:     "PUT",
		Path:       "/o/{organization_id}/webhooks",
		Summary:    "Update a variable. <br><b>Permission Required: </b>Edit Variable.",
		Positional: []string{"organization_id"},
		keywords:   codeOrchKeywords("o", "update", "Update a variable. <br><b>Permission Required: </b>Edit Variable.", "/o/{organization_id}/webhooks"),
	},
	{
		ID:         "oa.create",
		Method:     "POST",
		Path:       "/oa/benchmarks/query",
		Summary:    "Get a list of benchmark assets for an organization. <br><b>Permission Required: </b>View Benchmarks.",
		Positional: []string{},
		keywords:   codeOrchKeywords("oa", "create", "Get a list of benchmark assets for an organization. <br><b>Permission Required: </b>View Benchmarks.", "/oa/benchmarks/query"),
	},
	{
		ID:         "oa.create-ade",
		Method:     "POST",
		Path:       "/oa/ade/tokens/policies/query",
		Summary:    "Get a list of ade tokens assigned to policies.",
		Positional: []string{},
		keywords:   codeOrchKeywords("oa", "create-ade", "Get a list of ade tokens assigned to policies.", "/oa/ade/tokens/policies/query"),
	},
	{
		ID:         "oa.create-appsandbooks",
		Method:     "POST",
		Path:       "/oa/apps-and-books/tokens/policies/query",
		Summary:    "Get a list of apps and books tokens assigned to policies.",
		Positional: []string{},
		keywords:   codeOrchKeywords("oa", "create-appsandbooks", "Get a list of apps and books tokens assigned to policies.", "/oa/apps-and-books/tokens/policies/query"),
	},
	{
		ID:         "oa.create-compliancerules",
		Method:     "POST",
		Path:       "/oa/compliance-rules/query",
		Summary:    "Get a list of compliance rules for an organization. <br><b>Permission Required: </b>View Benchmarks.",
		Positional: []string{},
		keywords:   codeOrchKeywords("oa", "create-compliancerules", "Get a list of compliance rules for an organization. <br><b>Permission Required: </b>View Benchmarks.", "/oa/compliance-rules/query"),
	},
	{
		ID:         "oa.create-devices",
		Method:     "POST",
		Path:       "/oa/devices/compliance/status/query",
		Summary:    "Get devices compliance status. <br><b>Permission Required: </b>View Devices.",
		Positional: []string{},
		keywords:   codeOrchKeywords("oa", "create-devices", "Get devices compliance status. <br><b>Permission Required: </b>View Devices.", "/oa/devices/compliance/status/query"),
	},
	{
		ID:         "oa.create-files",
		Method:     "POST",
		Path:       "/oa/files/query",
		Summary:    "Get a list of files for an organization. <br><b>Permission Required:</b> View Files.",
		Positional: []string{},
		keywords:   codeOrchKeywords("oa", "create-files", "Get a list of files for an organization. <br><b>Permission Required:</b> View Files.", "/oa/files/query"),
	},
	{
		ID:         "oa.create-identity",
		Method:     "POST",
		Path:       "/oa/identity/configurations/policies/query",
		Summary:    "Get a list of identity configurations assigned to policies.",
		Positional: []string{},
		keywords:   codeOrchKeywords("oa", "create-identity", "Get a list of identity configurations assigned to policies.", "/oa/identity/configurations/policies/query"),
	},
	{
		ID:         "oa.create-installedapps",
		Method:     "POST",
		Path:       "/oa/installed-apps/mdm/query",
		Summary:    "Query installed apps from a device providing some agent IDs. <br><b>Permission Required:</b> View Devices.",
		Positional: []string{},
		keywords:   codeOrchKeywords("oa", "create-installedapps", "Query installed apps from a device providing some agent IDs. <br><b>Permission Required:</b> View Devices.", "/oa/installed-apps/mdm/query"),
	},
	{
		ID:         "oa.create-integrations",
		Method:     "POST",
		Path:       "/oa/integrations/azure-ca/accounts/metadata/query",
		Summary:    "Get Azure Conditional Access all accounts metadata.",
		Positional: []string{},
		keywords:   codeOrchKeywords("oa", "create-integrations", "Get Azure Conditional Access all accounts metadata.", "/oa/integrations/azure-ca/accounts/metadata/query"),
	},
	{
		ID:         "oa.create-monitoring",
		Method:     "POST",
		Path:       "/oa/monitoring/query",
		Summary:    "Query for a list of scheduled alerts with pagination.",
		Positional: []string{},
		keywords:   codeOrchKeywords("oa", "create-monitoring", "Query for a list of scheduled alerts with pagination.", "/oa/monitoring/query"),
	},
	{
		ID:         "oa.create-policies",
		Method:     "POST",
		Path:       "/oa/policies/query",
		Summary:    "Query an organization for all policies or filter to get specific policy info",
		Positional: []string{},
		keywords:   codeOrchKeywords("oa", "create-policies", "Query an organization for all policies or filter to get specific policy info", "/oa/policies/query"),
	},
	{
		ID:         "oa.create-policies-2",
		Method:     "POST",
		Path:       "/oa/policies/self_service/location/assets/query",
		Summary:    "Gets a list of available assets for the provided location ID (token ID).",
		Positional: []string{},
		keywords:   codeOrchKeywords("oa", "create-policies-2", "Gets a list of available assets for the provided location ID (token ID).", "/oa/policies/self_service/location/assets/query"),
	},
	{
		ID:         "oa.create-prebuiltapps",
		Method:     "POST",
		Path:       "/oa/prebuilt-apps/configurations/query",
		Summary:    "Query Prebuilt Apps Configurations",
		Positional: []string{},
		keywords:   codeOrchKeywords("oa", "create-prebuiltapps", "Query Prebuilt Apps Configurations", "/oa/prebuilt-apps/configurations/query"),
	},
	{
		ID:         "oa.create-reports",
		Method:     "POST",
		Path:       "/oa/reports/status/query",
		Summary:    "Get report statuses.",
		Positional: []string{},
		keywords:   codeOrchKeywords("oa", "create-reports", "Get report statuses.", "/oa/reports/status/query"),
	},
	{
		ID:         "oa.create-variables",
		Method:     "POST",
		Path:       "/oa/variables/query",
		Summary:    "Get a list of variables for an organization. <br><b>Permission Required: </b>View Variables.",
		Positional: []string{},
		keywords:   codeOrchKeywords("oa", "create-variables", "Get a list of variables for an organization. <br><b>Permission Required: </b>View Variables.", "/oa/variables/query"),
	},
	{
		ID:         "oa.create-webhooks",
		Method:     "POST",
		Path:       "/oa/webhooks/query",
		Summary:    "Get a list of webhooks.",
		Positional: []string{},
		keywords:   codeOrchKeywords("oa", "create-webhooks", "Get a list of webhooks.", "/oa/webhooks/query"),
	},
	{
		ID:         "oa.create-webhooks-2",
		Method:     "POST",
		Path:       "/oa/webhooks/schedule/count",
		Summary:    "Get a count of webhooks schedule.",
		Positional: []string{},
		keywords:   codeOrchKeywords("oa", "create-webhooks-2", "Get a count of webhooks schedule.", "/oa/webhooks/schedule/count"),
	},
	{
		ID:         "oa.create-webhooks-3",
		Method:     "POST",
		Path:       "/oa/webhooks/status/query",
		Summary:    "Get a list of webhooks status.",
		Positional: []string{},
		keywords:   codeOrchKeywords("oa", "create-webhooks-3", "Get a list of webhooks status.", "/oa/webhooks/status/query"),
	},
	{
		ID:         "oa.list",
		Method:     "GET",
		Path:       "/oa/homescreen",
		Summary:    "Get a policy home screen layout",
		Positional: []string{},
		keywords:   codeOrchKeywords("oa", "list", "Get a policy home screen layout", "/oa/homescreen"),
	},
	{
		ID:         "oa.list-benchmarks",
		Method:     "GET",
		Path:       "/oa/benchmarks/pre-built",
		Summary:    "Get pre-built benchmarks. <br><b>Permission Required: </b>View Benchmarks.",
		Positional: []string{},
		keywords:   codeOrchKeywords("oa", "list-benchmarks", "Get pre-built benchmarks. <br><b>Permission Required: </b>View Benchmarks.", "/oa/benchmarks/pre-built"),
	},
	{
		ID:         "oa.list-compliancerules",
		Method:     "GET",
		Path:       "/oa/compliance-rules/pre-built",
		Summary:    "Get pre-built compliance rules. <br><b>Permission Required: </b>View Benchmarks.",
		Positional: []string{},
		keywords:   codeOrchKeywords("oa", "list-compliancerules", "Get pre-built compliance rules. <br><b>Permission Required: </b>View Benchmarks.", "/oa/compliance-rules/pre-built"),
	},
	{
		ID:         "oa.list-compliancerules-2",
		Method:     "GET",
		Path:       "/oa/compliance-rules/usage",
		Summary:    "Get a compliance rule usage. <br><b>Permission Required: </b>View Benchmarks.",
		Positional: []string{},
		keywords:   codeOrchKeywords("oa", "list-compliancerules-2", "Get a compliance rule usage. <br><b>Permission Required: </b>View Benchmarks.", "/oa/compliance-rules/usage"),
	},
	{
		ID:         "oa.list-integrations",
		Method:     "GET",
		Path:       "/oa/integrations/azure-ca/tenants/metadata",
		Summary:    "Get Azure Conditional Access unique enabled tenants metadata",
		Positional: []string{},
		keywords:   codeOrchKeywords("oa", "list-integrations", "Get Azure Conditional Access unique enabled tenants metadata", "/oa/integrations/azure-ca/tenants/metadata"),
	},
	{
		ID:         "oa.list-reports",
		Method:     "GET",
		Path:       "/oa/reports",
		Summary:    "Get a report.",
		Positional: []string{},
		keywords:   codeOrchKeywords("oa", "list-reports", "Get a report.", "/oa/reports"),
	},
	{
		ID:         "oa.list-reports-2",
		Method:     "GET",
		Path:       "/oa/reports/available",
		Summary:    "Get a list of available reports.",
		Positional: []string{},
		keywords:   codeOrchKeywords("oa", "list-reports-2", "Get a list of available reports.", "/oa/reports/available"),
	},
	{
		ID:         "oa.list-selfservice",
		Method:     "GET",
		Path:       "/oa/self-service/policy/assigned",
		Summary:    "Get the self service configurations by OS for a policy",
		Positional: []string{},
		keywords:   codeOrchKeywords("oa", "list-selfservice", "Get the self service configurations by OS for a policy", "/oa/self-service/policy/assigned"),
	},
	{
		ID:         "prebuilt-apps.create",
		Method:     "POST",
		Path:       "/prebuilt-apps/versions",
		Summary:    "Create a Prebuilt App Version",
		Positional: []string{},
		keywords:   codeOrchKeywords("prebuilt-apps", "create", "Create a Prebuilt App Version", "/prebuilt-apps/versions"),
	},
	{
		ID:         "prebuilt-apps.create-prebuiltapps",
		Method:     "POST",
		Path:       "/prebuilt-apps/apps/",
		Summary:    "Create a prebuilt app",
		Positional: []string{},
		keywords:   codeOrchKeywords("prebuilt-apps", "create-prebuiltapps", "Create a prebuilt app", "/prebuilt-apps/apps/"),
	},
	{
		ID:         "prebuilt-apps.create-prebuiltapps-2",
		Method:     "POST",
		Path:       "/prebuilt-apps/apps/query",
		Summary:    "Query the prebuilt app library",
		Positional: []string{},
		keywords:   codeOrchKeywords("prebuilt-apps", "create-prebuiltapps-2", "Query the prebuilt app library", "/prebuilt-apps/apps/query"),
	},
	{
		ID:         "prebuilt-apps.create-prebuiltapps-3",
		Method:     "POST",
		Path:       "/prebuilt-apps/versions/query",
		Summary:    "Query Prebuilt App Versions",
		Positional: []string{},
		keywords:   codeOrchKeywords("prebuilt-apps", "create-prebuiltapps-3", "Query Prebuilt App Versions", "/prebuilt-apps/versions/query"),
	},
	{
		ID:         "prebuilt-apps.delete",
		Method:     "DELETE",
		Path:       "/prebuilt-apps/apps/{id}",
		Summary:    "Delete a prebuilt app",
		Positional: []string{"id"},
		keywords:   codeOrchKeywords("prebuilt-apps", "delete", "Delete a prebuilt app", "/prebuilt-apps/apps/{id}"),
	},
	{
		ID:         "prebuilt-apps.delete-prebuiltapps",
		Method:     "DELETE",
		Path:       "/prebuilt-apps/versions/{id}",
		Summary:    "Delete a Prebuilt App Version",
		Positional: []string{"id"},
		keywords:   codeOrchKeywords("prebuilt-apps", "delete-prebuiltapps", "Delete a Prebuilt App Version", "/prebuilt-apps/versions/{id}"),
	},
	{
		ID:         "prebuilt-apps.get",
		Method:     "GET",
		Path:       "/prebuilt-apps/apps/{id}",
		Summary:    "Get a prebuilt app",
		Positional: []string{"id"},
		keywords:   codeOrchKeywords("prebuilt-apps", "get", "Get a prebuilt app", "/prebuilt-apps/apps/{id}"),
	},
	{
		ID:         "prebuilt-apps.get-prebuiltapps",
		Method:     "GET",
		Path:       "/prebuilt-apps/versions/{id}",
		Summary:    "Get a Prebuilt App Version",
		Positional: []string{"id"},
		keywords:   codeOrchKeywords("prebuilt-apps", "get-prebuiltapps", "Get a Prebuilt App Version", "/prebuilt-apps/versions/{id}"),
	},
	{
		ID:         "prebuilt-apps.update",
		Method:     "PUT",
		Path:       "/prebuilt-apps/apps/{id}",
		Summary:    "Update a prebuilt app",
		Positional: []string{"id"},
		keywords:   codeOrchKeywords("prebuilt-apps", "update", "Update a prebuilt app", "/prebuilt-apps/apps/{id}"),
	},
	{
		ID:         "prebuilt-apps.update-prebuiltapps",
		Method:     "PUT",
		Path:       "/prebuilt-apps/versions/{id}",
		Summary:    "Update a Prebuilt App Version",
		Positional: []string{"id"},
		keywords:   codeOrchKeywords("prebuilt-apps", "update-prebuiltapps", "Update a Prebuilt App Version", "/prebuilt-apps/versions/{id}"),
	},
	{
		ID:         "self-service-configurations.create",
		Method:     "POST",
		Path:       "/self-service-configurations",
		Summary:    "Creates a new self service configuration in the organization. <br><b>Permission Required: </b>Create Instruction.",
		Positional: []string{},
		keywords:   codeOrchKeywords("self-service-configurations", "create", "Creates a new self service configuration in the organization. <br><b>Permission Required: </b>Create Instruction.", "/self-service-configurations"),
	},
	{
		ID:         "static-fields.create",
		Method:     "POST",
		Path:       "/static-fields",
		Summary:    "Creates a new static field in the organization. <br><b>Permission Required: </b>View Devices.",
		Positional: []string{},
		keywords:   codeOrchKeywords("static-fields", "create", "Creates a new static field in the organization. <br><b>Permission Required: </b>View Devices.", "/static-fields"),
	},
	{
		ID:         "static-fields.create-staticfields",
		Method:     "POST",
		Path:       "/static-fields/value",
		Summary:    "Assign static field values to device(s) in the organization. <br><b>Permission Required: </b>View Devices.",
		Positional: []string{},
		keywords:   codeOrchKeywords("static-fields", "create-staticfields", "Assign static field values to device(s) in the organization. <br><b>Permission Required: </b>View Devices.", "/static-fields/value"),
	},
	{
		ID:         "static-fields.delete",
		Method:     "DELETE",
		Path:       "/static-fields",
		Summary:    "Removes the static field from the organization. <br><b>Permission Required: </b>View Devices.",
		Positional: []string{},
		keywords:   codeOrchKeywords("static-fields", "delete", "Removes the static field from the organization. <br><b>Permission Required: </b>View Devices.", "/static-fields"),
	},
	{
		ID:         "static-fields.list",
		Method:     "GET",
		Path:       "/static-fields",
		Summary:    "Gets a list of all static fields available for the organization. <br><b>Permission Required: </b>View Devices.",
		Positional: []string{},
		keywords:   codeOrchKeywords("static-fields", "list", "Gets a list of all static fields available for the organization. <br><b>Permission Required: </b>View Devices.", "/static-fields"),
	},
	{
		ID:         "static-fields.list-staticfields",
		Method:     "GET",
		Path:       "/static-fields/value",
		Summary:    "Gets a list of all static fields assigned to devices for the organization. <br><b>Permission Required: </b>View Devices.",
		Positional: []string{},
		keywords:   codeOrchKeywords("static-fields", "list-staticfields", "Gets a list of all static fields assigned to devices for the organization. <br><b>Permission Required: </b>View Devices.", "/static-fields/value"),
	},
	{
		ID:         "static-fields.update",
		Method:     "PUT",
		Path:       "/static-fields",
		Summary:    "Updates the name of an existing static field in the organization. <br><b>Permission Required: </b>View Devices.",
		Positional: []string{},
		keywords:   codeOrchKeywords("static-fields", "update", "Updates the name of an existing static field in the organization. <br><b>Permission Required: </b>View Devices.", "/static-fields"),
	},
	{
		ID:         "system-events.create",
		Method:     "POST",
		Path:       "/system-events/query",
		Summary:    "Allow to query for a set of system events. <br><b>Permission Required: </b>View System Events.",
		Positional: []string{},
		keywords:   codeOrchKeywords("system-events", "create", "Allow to query for a set of system events. <br><b>Permission Required: </b>View System Events.", "/system-events/query"),
	},
	{
		ID:         "system-events.create-systemevents",
		Method:     "POST",
		Path:       "/system-events/search",
		Summary:    "Allow to search system events. <br><b>Permission Required: </b>View System Events.",
		Positional: []string{},
		keywords:   codeOrchKeywords("system-events", "create-systemevents", "Allow to search system events. <br><b>Permission Required: </b>View System Events.", "/system-events/search"),
	},
	{
		ID:         "system-updates.create",
		Method:     "POST",
		Path:       "/system-updates/available",
		Summary:    "Requests available system updates for a device via MDM command.<br><br><b>Permission Required: </b>View Device List,...",
		Positional: []string{},
		keywords:   codeOrchKeywords("system-updates", "create", "Requests available system updates for a device via MDM command.<br><br><b>Permission Required: </b>View Device List,...", "/system-updates/available"),
	},
	{
		ID:         "system-updates.create-systemupdates",
		Method:     "POST",
		Path:       "/system-updates/scan",
		Summary:    "Requests a system updates scan for a device via MDM command.<br><br><b>Permission Required: </b>View Device List,...",
		Positional: []string{},
		keywords:   codeOrchKeywords("system-updates", "create-systemupdates", "Requests a system updates scan for a device via MDM command.<br><br><b>Permission Required: </b>View Device List,...", "/system-updates/scan"),
	},
	{
		ID:         "system-updates.create-systemupdates-2",
		Method:     "POST",
		Path:       "/system-updates/schedule",
		Summary:    "Requests the schedule of system updates via MDM command.<br><br><b>Permission Required: </b>View Device List,...",
		Positional: []string{},
		keywords:   codeOrchKeywords("system-updates", "create-systemupdates-2", "Requests the schedule of system updates via MDM command.<br><br><b>Permission Required: </b>View Device List,...", "/system-updates/schedule"),
	},
	{
		ID:         "system-updates.create-systemupdates-3",
		Method:     "POST",
		Path:       "/system-updates/settings",
		Summary:    "Requests to create or update system updates settings for a policy.<br><br><b>Permission Required: </b>Create System...",
		Positional: []string{},
		keywords:   codeOrchKeywords("system-updates", "create-systemupdates-3", "Requests to create or update system updates settings for a policy.<br><br><b>Permission Required: </b>Create System...", "/system-updates/settings"),
	},
	{
		ID:         "system-updates.create-systemupdates-4",
		Method:     "POST",
		Path:       "/system-updates/status",
		Summary:    "Requests system updates statuses for a device via MDM command.<br><br><b>Permission Required: </b>View Device List,...",
		Positional: []string{},
		keywords:   codeOrchKeywords("system-updates", "create-systemupdates-4", "Requests system updates statuses for a device via MDM command.<br><br><b>Permission Required: </b>View Device List,...", "/system-updates/status"),
	},
	{
		ID:         "system-updates.create-systemupdates-5",
		Method:     "POST",
		Path:       "/system-updates/available/query",
		Summary:    "Gets available updates reported for multiple devices",
		Positional: []string{},
		keywords:   codeOrchKeywords("system-updates", "create-systemupdates-5", "Gets available updates reported for multiple devices", "/system-updates/available/query"),
	},
	{
		ID:         "system-updates.create-systemupdates-6",
		Method:     "POST",
		Path:       "/system-updates/installed/query",
		Summary:    "Gets installed system updates reported for multiple devices",
		Positional: []string{},
		keywords:   codeOrchKeywords("system-updates", "create-systemupdates-6", "Gets installed system updates reported for multiple devices", "/system-updates/installed/query"),
	},
	{
		ID:         "system-updates.create-systemupdates-7",
		Method:     "POST",
		Path:       "/system-updates/on-demand/device-uuids",
		Summary:    "Requests to schedule system updates (on-demand) for devices via MDM command.<br><br><b>Permission Required:...",
		Positional: []string{},
		keywords:   codeOrchKeywords("system-updates", "create-systemupdates-7", "Requests to schedule system updates (on-demand) for devices via MDM command.<br><br><b>Permission Required:...", "/system-updates/on-demand/device-uuids"),
	},
	{
		ID:         "system-updates.create-systemupdates-8",
		Method:     "POST",
		Path:       "/system-updates/on-demand/policy-id",
		Summary:    "Requests to schedule system updates (on-demand) for policy devices via MDM command.<br><br><b>Permission Required:...",
		Positional: []string{},
		keywords:   codeOrchKeywords("system-updates", "create-systemupdates-8", "Requests to schedule system updates (on-demand) for policy devices via MDM command.<br><br><b>Permission Required:...", "/system-updates/on-demand/policy-id"),
	},
	{
		ID:         "system-updates.create-systemupdates-9",
		Method:     "POST",
		Path:       "/system-updates/installed/organization/report/email",
		Summary:    "Requests to send installed system updates reported for policy devices to user email.<br><br><b>Permission Required:...",
		Positional: []string{},
		keywords:   codeOrchKeywords("system-updates", "create-systemupdates-9", "Requests to send installed system updates reported for policy devices to user email.<br><br><b>Permission Required:...", "/system-updates/installed/organization/report/email"),
	},
	{
		ID:         "system-updates.list",
		Method:     "GET",
		Path:       "/system-updates/available",
		Summary:    "Gets available system updates reported for a device.<br><br><b>Permission Required: </b>View Device List.",
		Positional: []string{},
		keywords:   codeOrchKeywords("system-updates", "list", "Gets available system updates reported for a device.<br><br><b>Permission Required: </b>View Device List.", "/system-updates/available"),
	},
	{
		ID:         "system-updates.list-systemupdates",
		Method:     "GET",
		Path:       "/system-updates/latest",
		Summary:    "Get latest system updates available by os type",
		Positional: []string{},
		keywords:   codeOrchKeywords("system-updates", "list-systemupdates", "Get latest system updates available by os type", "/system-updates/latest"),
	},
	{
		ID:         "system-updates.list-systemupdates-2",
		Method:     "GET",
		Path:       "/system-updates/settings",
		Summary:    "Gets system updates settings for a policy.<br><br><b>Permission Required: </b>View System Updates Settings.",
		Positional: []string{},
		keywords:   codeOrchKeywords("system-updates", "list-systemupdates-2", "Gets system updates settings for a policy.<br><br><b>Permission Required: </b>View System Updates Settings.", "/system-updates/settings"),
	},
	{
		ID:         "system-updates.list-systemupdates-3",
		Method:     "GET",
		Path:       "/system-updates/status",
		Summary:    "Gets current system updates statuses reported for a device.<br><br><b>Permission Required: </b>View Device List,...",
		Positional: []string{},
		keywords:   codeOrchKeywords("system-updates", "list-systemupdates-3", "Gets current system updates statuses reported for a device.<br><br><b>Permission Required: </b>View Device List,...", "/system-updates/status"),
	},
	{
		ID:         "system-updates.list-systemupdates-4",
		Method:     "GET",
		Path:       "/system-updates/available/status",
		Summary:    "Gets available system updates reported for a device, with their current installation statuses.<br><br><b>Permission...",
		Positional: []string{},
		keywords:   codeOrchKeywords("system-updates", "list-systemupdates-4", "Gets available system updates reported for a device, with their current installation statuses.<br><br><b>Permission...", "/system-updates/available/status"),
	},
	{
		ID:         "system-updates.list-systemupdates-5",
		Method:     "GET",
		Path:       "/system-updates/ddm/status",
		Summary:    "Gets device system updates statuses via ddm status report.<br><br><b>Permission Required: </b>View Device List.",
		Positional: []string{},
		keywords:   codeOrchKeywords("system-updates", "list-systemupdates-5", "Gets device system updates statuses via ddm status report.<br><br><b>Permission Required: </b>View Device List.", "/system-updates/ddm/status"),
	},
	{
		ID:         "system-updates.list-systemupdates-6",
		Method:     "GET",
		Path:       "/system-updates/installed/device/report",
		Summary:    "Gets installed system updates reported for a device.<br><br><b>Permission Required: </b>View System Updates Settings.",
		Positional: []string{},
		keywords:   codeOrchKeywords("system-updates", "list-systemupdates-6", "Gets installed system updates reported for a device.<br><br><b>Permission Required: </b>View System Updates Settings.", "/system-updates/installed/device/report"),
	},
	{
		ID:         "users.create",
		Method:     "POST",
		Path:       "/users",
		Summary:    "Create a user. <br><b>Permission Required: </b>Create User.",
		Positional: []string{},
		keywords:   codeOrchKeywords("users", "create", "Create a user with an optional role and policy restrictions. <br><b>Permission Required: </b>Create User.", "/users"),
	},
	{
		ID:         "users.delete",
		Method:     "DELETE",
		Path:       "/users",
		Summary:    "Deletes a user from the organization. <br><b>Permission Required: </b>Remove User.",
		Positional: []string{},
		keywords:   codeOrchKeywords("users", "delete", "Deletes a user from the organization. <br><b>Permission Required: </b>Remove User.", "/users"),
	},
	{
		ID:         "users.update",
		Method:     "PUT",
		Path:       "/users",
		Summary:    "Update a user. <br><b>Permission Required: </b>Edit User.",
		Positional: []string{},
		keywords:   codeOrchKeywords("users", "update", "Update a user. <br><b>Permission Required: </b>Edit User.", "/users"),
	},
}

// codeOrchStopwords filters two-letter and short common-word substrings
// that pollute ranking via the substring-contains rule. Without them, a
// search for "list links" matches every endpoint whose description
// contains "is enrolled" because "is" is two chars and the matcher
// accepts kw.contains(t) || t.contains(kw).
var codeOrchStopwords = map[string]bool{
	"a": true, "an": true, "and": true, "are": true, "as": true,
	"at": true, "be": true, "by": true, "for": true, "from": true,
	"has": true, "in": true, "is": true, "it": true, "its": true,
	"of": true, "on": true, "or": true, "that": true, "the": true,
	"this": true, "to": true, "was": true, "will": true, "with": true,
	"your": true, "you": true, "any": true, "all": true,
}

// codeOrchKeywords produces the lowercase token stream used for search
// ranking. Defined at package level so the registry initializer can call it
// inline above without pulling in a separate precompute step.
func codeOrchKeywords(resource, endpoint, summary, path string) []string {
	raw := strings.ToLower(resource + " " + endpoint + " " + summary + " " + path)
	raw = strings.Map(func(r rune) rune {
		switch r {
		case '_', '-', '/', '{', '}', '.', ',', ':', ';':
			return ' '
		}
		return r
	}, raw)
	out := make([]string, 0, 16)
	seen := map[string]bool{}
	for _, tok := range strings.Fields(raw) {
		if len(tok) < 3 || codeOrchStopwords[tok] || seen[tok] {
			continue
		}
		seen[tok] = true
		out = append(out, tok)
	}
	return out
}

func handleCodeOrchSearch(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	args := req.GetArguments()
	query, ok := args["query"].(string)
	if !ok || strings.TrimSpace(query) == "" {
		return mcplib.NewToolResultError("query is required"), nil
	}
	limit := 10
	if v, ok := args["limit"].(float64); ok && v > 0 {
		limit = int(v)
	}

	terms := codeOrchKeywords("", "", query, "")
	type scored struct {
		ep    *codeOrchEndpoint
		score int
	}
	results := make([]scored, 0, len(codeOrchEndpoints))
	for i := range codeOrchEndpoints {
		ep := &codeOrchEndpoints[i]
		score := 0
		for _, t := range terms {
			for _, kw := range ep.keywords {
				if kw == t {
					score += 2
				} else if strings.Contains(kw, t) || strings.Contains(t, kw) {
					score++
				}
			}
		}
		if score > 0 {
			results = append(results, scored{ep: ep, score: score})
		}
	}
	sort.SliceStable(results, func(i, j int) bool { return results[i].score > results[j].score })
	if len(results) > limit {
		results = results[:limit]
	}

	out := make([]map[string]any, 0, len(results))
	for _, r := range results {
		out = append(out, map[string]any{
			"endpoint_id": r.ep.ID,
			"method":      r.ep.Method,
			"path":        r.ep.Path,
			"summary":     r.ep.Summary,
			"score":       r.score,
		})
	}
	data, _ := json.Marshal(map[string]any{"count": len(out), "results": out})
	return mcplib.NewToolResultText(string(data)), nil
}

func handleCodeOrchExecute(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	args := req.GetArguments()
	id, ok := args["endpoint_id"].(string)
	if !ok || id == "" {
		return mcplib.NewToolResultError("endpoint_id is required (call addigy_search first)"), nil
	}

	var ep *codeOrchEndpoint
	for i := range codeOrchEndpoints {
		if codeOrchEndpoints[i].ID == id {
			ep = &codeOrchEndpoints[i]
			break
		}
	}
	if ep == nil {
		return mcplib.NewToolResultError(fmt.Sprintf("unknown endpoint_id %q — call addigy_search to discover valid ids", id)), nil
	}

	params, _ := args["params"].(map[string]any)
	if params == nil {
		params = map[string]any{}
	}

	c, err := newMCPClient()
	if err != nil {
		return mcplib.NewToolResultError(err.Error()), nil
	}

	path := ep.Path
	for _, p := range ep.Positional {
		if v, ok := params[p]; ok {
			path = strings.ReplaceAll(path, "{"+p+"}", fmt.Sprintf("%v", v))
			delete(params, p)
		}
	}

	query := map[string]string{}
	if ep.Method == "GET" || ep.Method == "DELETE" {
		for k, v := range params {
			query[k] = fmt.Sprintf("%v", v)
		}
	}

	data, err := execEndpointRequest(c, ep.Method, path, query, params)
	if err != nil {
		return mcplib.NewToolResultError(err.Error()), nil
	}
	return mcplib.NewToolResultText(string(data)), nil
}

// execEndpointRequest dispatches one API call by HTTP method. GET and DELETE
// carry their identifying params in the query string (the v2 API keys deletes
// on ?id=/?key=); POST/PUT/PATCH carry params in the JSON body. Extracted from
// the handler so request construction is unit-testable (the handler builds its
// own client from on-disk config).
func execEndpointRequest(c *client.Client, method, path string, query map[string]string, params map[string]any) (json.RawMessage, error) {
	switch method {
	case "GET":
		return c.Get(path, query)
	case "DELETE":
		data, _, err := c.DeleteWithParams(path, query)
		return data, err
	case "POST", "PUT", "PATCH":
		body, err := json.Marshal(params)
		if err != nil {
			return nil, fmt.Errorf("marshaling body: %w", err)
		}
		switch method {
		case "POST":
			data, _, err := c.Post(path, body)
			return data, err
		case "PUT":
			data, _, err := c.Put(path, body)
			return data, err
		default:
			data, _, err := c.Patch(path, body)
			return data, err
		}
	default:
		return nil, fmt.Errorf("unsupported method %q", method)
	}
}
