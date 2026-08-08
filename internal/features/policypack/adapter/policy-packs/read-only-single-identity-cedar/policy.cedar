// Rename REPLACE_WITH_YOUR_IDENTITY to your real identity, and edit the
// tool names below to match what your MCP server actually exposes --
// read_file/list_files/get_status are examples, not universal tool
// names. One permit statement per allowed tool (Cedar's scope clauses
// don't support a set-literal resource match, only a single resource or
// a hierarchy "in" check) -- add or remove statements to match your
// actual read/list-shaped tool list.
permit(
  principal == Wardline::Identity::"REPLACE_WITH_YOUR_IDENTITY",
  action == Wardline::Action::"call_tool",
  resource == Wardline::Tool::"read_file"
);

permit(
  principal == Wardline::Identity::"REPLACE_WITH_YOUR_IDENTITY",
  action == Wardline::Action::"call_tool",
  resource == Wardline::Tool::"list_files"
);

permit(
  principal == Wardline::Identity::"REPLACE_WITH_YOUR_IDENTITY",
  action == Wardline::Action::"call_tool",
  resource == Wardline::Tool::"get_status"
);
