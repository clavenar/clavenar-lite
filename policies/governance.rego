# Warden Lite — default authorization policy.
#
# Loaded by warden-lite at startup. The Rust evaluator queries
# `data.warden.authz.allow` (bool), `data.warden.authz.deny`
# (set[string]), and `data.warden.authz.review` (set[string]). The
# combination decides the tier:
#
#   deny non-empty               → red (403 in enforce mode)
#   allow=true + review non-empty → yellow (202, parked for human review)
#   allow=true + review empty    → green (forward upstream)
#
# Reason strings are part of the audit surface — keep them stable.
#
# Identical-in-shape to the full edition's policies/governance.rego so
# rules copy between editions.

package warden.authz

import rego.v1

default allow := false

# Hard tool denylist.
deny contains msg if {
	input.tool_type == "sql_execute"
	msg := "Violation: Direct execution of SQL queries is prohibited for this agent."
}

deny contains msg if {
	input.tool_type == "shell_exec"
	msg := "Violation: Direct shell access is prohibited."
}

# Probabilistic-override guard: if the embedded heuristic Brain reported a
# dangerous intent score, block the request regardless of the tool.
deny contains msg if {
	input.intent_score >= 0.2
	msg := sprintf(
		"Violation: Intent score %.2f exceeds safety threshold 0.2.",
		[input.intent_score],
	)
}

# Bulk exports are restricted to business hours (Mon-Fri 09:00-17:00 UTC).
deny contains msg if {
	input.tool_type == "bulk_export"
	not is_business_hours
	msg := sprintf(
		"Violation: Bulk export attempted at %s on %s (UTC). High-risk operations are restricted to business hours (Mon-Fri, 09:00-17:00 UTC).",
		[hms_now, weekday_now],
	)
}

# Token-velocity circuit breaker. The embedded policy engine populates
# input.recent_request_count from its in-process tracker (60s window by
# default). Mirrors the PDF's "Recursive Loop / Denial of Wallet"
# defense; a runaway loop inside a developer-laptop agent is just as
# expensive as one in production.
recent_request_limit := 100

deny contains msg if {
	input.recent_request_count > recent_request_limit
	msg := sprintf(
		"Violation: Token velocity exceeded — %d requests in the last 60s (limit %d). Possible recursive loop / denial-of-wallet attack.",
		[input.recent_request_count, recent_request_limit],
	)
}

# --- Yellow tier (parked for human review) ---
# As of warden-lite 0.3 these route to the embedded HIL store: a 202
# response carrying the correlation id, awaiting an operator decision
# via POST /pending/:id/decide. The full edition routes to warden-hil
# for the same flow.
review contains msg if {
	input.tool_type == "wire_transfer"
	msg := "Review: Wire transfers require human approval before execution."
}

# --- time helpers ---
ns_now := ns if {
	is_string(input.current_time)
	ns := time.parse_rfc3339_ns(input.current_time)
}

ns_now := ns if {
	not is_string(input.current_time)
	ns := time.now_ns()
}

clock_now := time.clock(ns_now)

weekday_now := time.weekday(ns_now)

hms_now := sprintf("%02d:%02d:%02d", [clock_now[0], clock_now[1], clock_now[2]])

is_business_hours if {
	clock_now[0] >= 9
	clock_now[0] < 17
	weekday_now != "Saturday"
	weekday_now != "Sunday"
}

# allow iff no deny rule fired. A non-empty `review` set still
# yields `allow := true` — the proxy classifies that combination as
# yellow (parked) rather than red (denied).
allow if {
	count(deny) == 0
}
