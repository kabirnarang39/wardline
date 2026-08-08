// Rename REPLACE_WITH_YOUR_IDENTITY to your real identity (the value your
// client sends via X-Wardline-Identity, or your verified bearer subject
// when credential_issuance is on) before using this file.
permit(
  principal == Wardline::Identity::"REPLACE_WITH_YOUR_IDENTITY",
  action == Wardline::Action::"call_tool",
  resource
);
