package wardline.authz

# Rename REPLACE_WITH_YOUR_IDENTITY to your real identity (the value your
# client sends via X-Wardline-Identity, or your verified bearer subject
# when credential_issuance is on) before using this file.
default allow = false

allow {
	input.identity == "REPLACE_WITH_YOUR_IDENTITY"
}
