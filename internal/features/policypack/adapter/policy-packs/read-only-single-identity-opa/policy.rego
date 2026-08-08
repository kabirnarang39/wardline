package wardline.authz

# Rename REPLACE_WITH_YOUR_IDENTITY to your real identity, and edit the
# tool names below to match what your MCP server actually exposes --
# read_file/list_files/get_status are examples, not universal tool names.
default allow = false

read_tools := {"read_file", "list_files", "get_status"}

allow {
	input.identity == "REPLACE_WITH_YOUR_IDENTITY"
	read_tools[input.tool]
}
