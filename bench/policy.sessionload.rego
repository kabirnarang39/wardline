package wardline.authz

# Combined taint + approval policy for bench/sessionload, mirroring
# cmd/wardline/e2e_taint_test.go's taintPolicy and
# e2e_approval_test.go's approvalE2EPolicy exactly: a tainted write
# needs approval (not an outright deny) so one policy file serves both
# the "taint" and "approval" sessionload modes -- taint mode never
# turns approval_workflow on, so `needs`/`approval` are simply never
# reached there and the tainted write fails closed at 403 (the same
# TestServeEndToEnd_ApprovalOffFailsClosed behavior), which is exactly
# what runTaintSession asserts.

default allow = false


# is_write excludes web_fetch (the untrusted READ source) explicitly --
# without this, "any tools/call" also matches the read itself, so a
# SECOND read attempt after the session is already tainted would be
# denied too (is_write -> needs -> approval/deny), breaking every
# iteration after the first in sessionload's repeated read-then-write
# cycle. cmd/wardline/e2e_taint_test.go's taintPolicy never hits this:
# its tests read once, write once, never read again on the same
# session.
is_write {
	input.method == "tools/call"
	input.tool != "web_fetch"
}

needs {
	input.tainted
	is_write
}

approval {
	needs
}

allow {
	input.identity == "bench-agent"
	not needs
}
