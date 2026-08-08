package wardline.authz

# Rename REPLACE_WITH_ADMIN_IDENTITY and REPLACE_WITH_VIEWER_IDENTITY to
# your real identities -- they MUST be two DIFFERENT strings. Also edit
# the viewer's tool list to match what your MCP server actually exposes.
#
# The admin rule's "input.identity != REPLACE_WITH_VIEWER_IDENTITY" guard
# exists so that if both placeholders get renamed to the SAME identity by
# mistake, that identity keeps only the viewer's read access instead of
# silently gaining full access -- unlike a plain OR of independent rules,
# where an unguarded admin rule would grant full access regardless of
# what the viewer rule also allows.
default allow = false

read_tools := {"read_file", "list_files", "get_status"}

allow {
	input.identity == "REPLACE_WITH_ADMIN_IDENTITY"
	input.identity != "REPLACE_WITH_VIEWER_IDENTITY"
}

allow {
	input.identity == "REPLACE_WITH_VIEWER_IDENTITY"
	read_tools[input.tool]
}
