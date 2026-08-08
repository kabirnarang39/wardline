// Rename REPLACE_WITH_ADMIN_IDENTITY and REPLACE_WITH_VIEWER_IDENTITY to
// your real identities -- they MUST be two DIFFERENT strings. Also edit
// the viewer's tool list to match what your MCP server actually exposes.
//
// The admin permit's "when" guard exists so that if both placeholders
// get renamed to the SAME identity by mistake, that identity keeps only
// the viewer's read access instead of silently gaining full access --
// unlike two independent unconditional permits, where an unguarded admin
// permit would grant full access regardless of what the viewer permit
// also allows (Cedar permits are additive: any matching permit allows).
permit(
  principal == Wardline::Identity::"REPLACE_WITH_ADMIN_IDENTITY",
  action == Wardline::Action::"call_tool",
  resource
) when {
  principal != Wardline::Identity::"REPLACE_WITH_VIEWER_IDENTITY"
};

permit(
  principal == Wardline::Identity::"REPLACE_WITH_VIEWER_IDENTITY",
  action == Wardline::Action::"call_tool",
  resource == Wardline::Tool::"read_file"
);

permit(
  principal == Wardline::Identity::"REPLACE_WITH_VIEWER_IDENTITY",
  action == Wardline::Action::"call_tool",
  resource == Wardline::Tool::"list_files"
);

permit(
  principal == Wardline::Identity::"REPLACE_WITH_VIEWER_IDENTITY",
  action == Wardline::Action::"call_tool",
  resource == Wardline::Tool::"get_status"
);
