#!/usr/bin/env bash
# Copyright 2026 The OpenSandbox Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# verify/sandbox.sh — end-to-end sandbox verify (CLI create -> gateway -> execd /ping)
#
# Cold + warm sandbox creates through the full wire-up, egress policy enforcement and update convergence, and the remaining lifecycle surface (get/list/metadata/renew).
# Runs as part of `integration.sh up` (the entry chains every verify
# script) or standalone against a live stack from `env.sh up`.

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib.sh"

verify_policy_enforced() {
	local out
	out="$(server_api GET "/sandboxes/$VERIFY_ID/networkpolicy" 2>/dev/null)" || return 1
	[[ "$(printf '%s' "$out" | jq -r '.mode // empty')" == "enforcing" ]] || return 1
	[[ "$(printf '%s' "$out" | jq -r '.policy.egress[0].target // empty')" == "example.com" ]]
}

verify_policy_updated() {
	local out
	out="$(server_api GET "/sandboxes/$VERIFY_ID/networkpolicy" 2>/dev/null)" || return 1
	[[ "$(printf '%s' "$out" | jq -r '.mode // empty')" == "enforcing" ]] || return 1
	[[ "$(printf '%s' "$out" | jq -r '.policy.egress[0].target // empty')" == "github.com" ]]
}

# Full wire-up: CLI create (fsb) -> FastPath -> fastlet -> firecracker
# sandbox -> signed gateway route -> fastlet-proxy -> guest execd /ping ->
# delete. One sandbox per call; availability is measured from the client
# (poll /ping until 200, wall-clock budget — each route poll is a CLI call,
# ~0.5s startup), not from CR status.
verify_one_sandbox() { # <label> <ping-budget-ms>
	local label="$1" budget="$2" created t0 t1 t2 route code deadline
	local policy_file="$GEN_DIR/verify-policy.json"
	t0="$(now_ms)"
	# Egress policy rides on every create (binding -> nft rules), so the
	# chain is exercised each time; /ping is inbound and unaffected.
	jq -n '{defaultAction: "deny", egress: [{action: "allow", target: "example.com"}, {action: "allow", target: "*.opensandbox.ai"}]}' \
		> "$policy_file"
	log "verify ($label): creating a sandbox via the opensandbox CLI (templateId=$TEMPLATE_ID)"
	created="$(osb_api sandbox create --template "$TEMPLATE_ID" --timeout 1h \
		--metadata origin=fast-sandbox-env-verify \
		--network-policy-file "$policy_file" \
		--skip-health-check -o json 2>/dev/null)" \
		|| fail "osb sandbox create failed against $SERVER_URL: $(osb_api sandbox create \
			--template "$TEMPLATE_ID" --timeout 1h --skip-health-check 2>&1 >/dev/null | head -c 400)"
	VERIFY_ID="$(printf '%s' "$created" | jq -r '.id')"
	[[ -n "$VERIFY_ID" && "$VERIFY_ID" != "null" ]] || fail "create response carried no id"
	t1="$(now_ms)"
	# Availability = /ping 200 through the signed gateway route (port 44772).
	deadline=$(( t1 + budget * 1000000 ))
	while :; do
		route="$(osb_api sandbox endpoint "$VERIFY_ID" --port 44772 -o json 2>/dev/null \
			| jq -r '.headers["OpenSandbox-Ingress-To"] // empty')"
		if [[ -n "$route" ]]; then
			code="$(curl -sS -m 5 -o /dev/null -w '%{http_code}' \
				-H "OpenSandbox-Ingress-To: $route" "$GATEWAY_URL/ping" 2>/dev/null || true)"
			[[ "$code" == "200" ]] && break
		fi
		if (( $(now_ms) >= deadline )); then
			fail "execd /ping did not return 200 within ${budget}ms (last code=${code:-none}, route=${route:-none})"
		fi
		sleep 0.2
	done
	t2="$(now_ms)"
	# jq filter in a variable: literal parens trip older bash's $( ) parser.
	local state raw raw_filter
	raw_filter='{rt:.status.runtime.state,dp:.status.dataPlane.state,infra:[.status.infraComponents[]?|{n:.name,s:.state}],bind:[.status.actionBindings[]?|{h:.handler,s:.state}],ready:(.status.conditions[]?|select(.type=="Ready")|.status)}'
	state="$(osb_api sandbox get "$VERIFY_ID" -o json 2>/dev/null | jq -r '.status.state // empty')"
	raw="$(kubectl -n "$RESOURCE_NS" get sandbox "$VERIFY_ID" -o json 2>/dev/null | jq -c "$raw_filter")"
	log "verify ($label): $VERIFY_ID access via ingress gateway: curl -H \"OpenSandbox-Ingress-To: $route\" $GATEWAY_URL/ping"
	log "verify ($label): $VERIFY_ID create $(( (t1 - t0) / 1000000 ))ms, create->execd /ping 200 $(( (t2 - t1) / 1000000 ))ms, total $(( (t2 - t0) / 1000000 ))ms"
	log "verify ($label): CR at ping: server=$state raw=${raw:-unreachable}"
	pass "execd /ping 200 through the signed gateway route (44772)"
	wait_for "egress policy enforcing (networkPolicy -> egress action binding -> nft)" 120 verify_policy_enforced
	# Policy UPDATE path (raw PUT: the CLI only has merge-style patches).
	local put_body
	put_body="$(jq -n '{defaultAction: "deny", egress: [{action: "allow", target: "github.com"}]}')"
	server_api PUT "/sandboxes/$VERIFY_ID/networkpolicy" "$put_body" >/dev/null \
		|| fail "PUT networkpolicy failed for $VERIFY_ID: $(printf '%s' "$put_body" | head -c 200)"
	wait_for "policy update converged (PUT -> ReplaceActionBindings -> egress)" 120 verify_policy_updated
	# Re-sample the CR state: an early Failed observation may converge late.
	local state_final
	state_final="$(osb_api sandbox get "$VERIFY_ID" -o json 2>/dev/null | jq -r '.status.state // empty')"
	log "verify ($label): $VERIFY_ID CR state final: ${state_final:-unknown}"
}

# Remaining lifecycle surface on one sandbox: get, list, metadata merge-patch
# (raw API — no CLI command), renew via the CLI (TTL-based).
verify_lifecycle_ops() { # <sandbox-id>
	local id="$1" out expected_expires renewed_expires
	out="$(osb_api sandbox get "$id" -o json 2>/dev/null)" || fail "osb sandbox get $id failed"
	[[ "$(printf '%s' "$out" | jq -r '.id')" == "$id" ]] || fail "GET returned wrong id: $out"
	pass "lifecycle: osb sandbox get"

	osb_api sandbox list --page 1 --page-size 50 -o json > "$WORK/last-list.json" 2>"$WORK/last-list.err" \
		|| fail "osb sandbox list failed: $(head -c 400 "$WORK/last-list.err" 2>/dev/null)"
	out="$(cat "$WORK/last-list.json")"
	[[ "$(printf '%s' "$out" | jq -r --arg id "$id" '.items[]?.id | select(. == $id)' | head -1)" == "$id" ]] \
		|| fail "list does not contain $id: $(printf '%s' "$out" | jq -c '.pagination')"
	pass "lifecycle: osb sandbox list (contains the verify sandbox)"

	# JSON Merge Patch (RFC 7396): non-null upserts, null deletes.
	server_api PATCH "/sandboxes/$id/metadata" '{"env":"verify","stage":"lifecycle-ops"}' >/dev/null \
		|| fail "PATCH metadata upsert failed"
	out="$(osb_api sandbox get "$id" -o json 2>/dev/null)"
	[[ "$(printf '%s' "$out" | jq -r '.metadata.env')" == "verify" \
		&& "$(printf '%s' "$out" | jq -r '.metadata.stage')" == "lifecycle-ops" ]] \
		|| fail "metadata upsert not visible: $(printf '%s' "$out" | jq -c '.metadata')"
	server_api PATCH "/sandboxes/$id/metadata" '{"stage":null}' >/dev/null \
		|| fail "PATCH metadata delete failed"
	out="$(osb_api sandbox get "$id" -o json 2>/dev/null)"
	[[ "$(printf '%s' "$out" | jq -r '.metadata.stage')" == "null" \
		&& "$(printf '%s' "$out" | jq -r '.metadata.env')" == "verify" ]] \
		|| fail "metadata delete not visible: $(printf '%s' "$out" | jq -c '.metadata')"
	pass "lifecycle: PATCH metadata (upsert + null-delete via JSON Merge Patch)"

	# CLI renew takes a TTL: assert the expiration advanced and is visible.
	expected_expires="$(osb_api sandbox get "$id" -o json 2>/dev/null | jq -r '.expires_at')"
	out="$(osb_api sandbox renew "$id" --timeout 2h -o json 2>"$WORK/last-renew.err")" \
		|| fail "osb sandbox renew failed: $(head -c 400 "$WORK/last-renew.err" 2>/dev/null)"
	renewed_expires="$(printf '%s' "$out" | jq -r '.expires_at')"
	[[ -n "$renewed_expires" && "$renewed_expires" != "null" && "$renewed_expires" != "$expected_expires" ]] \
		|| fail "renewed expiresAt did not advance: $expected_expires -> $renewed_expires"
	local got_expires
	got_expires="$(osb_api sandbox get "$id" -o json 2>/dev/null | jq -r '.expires_at')"
	# Same instant, two renderings (renew panel str() vs RFC3339 dump):
	# compare epoch seconds, falling back to string equality.
	if [[ "$got_expires" != "$renewed_expires" ]] \
		&& [[ "$(date -u -d "$renewed_expires" +%s 2>/dev/null || true)" \
			!= "$(date -u -d "$got_expires" +%s 2>/dev/null || true)" ]]; then
		fail "renewed expiresAt not visible: expected $renewed_expires got $got_expires"
	fi
	pass "lifecycle: osb sandbox renew 2h ($expected_expires -> $renewed_expires)"
}

opensandbox_verify() {
	# Cold create pulls the golden image through DART (slowest; generous
	# budget). Warm creates: the second may still pull on the other node via
	# its DART peer; after both nodes cache the set, creates are sub-second.
	local ids=() id label index
	verify_one_sandbox "cold #1" 600000
	ids+=("$VERIFY_ID")
	verify_one_sandbox "warm #2" 600000
	ids+=("$VERIFY_ID")
	for index in 3 4 5 6; do
		verify_one_sandbox "warm #$index" 120000
		ids+=("$VERIFY_ID")
	done
	pass "end-to-end: opensandbox CLI -> server -> FastPath -> fastlet -> sandbox execd -> gateway route OK (6 sandboxes)"
	verify_lifecycle_ops "${ids[0]}"
	for id in "${ids[@]}"; do
		VERIFY_ID="$id"
		osb_api sandbox kill "$id" >/dev/null 2>&1 \
			|| log "verify cleanup: kill failed; remove $id manually"
	done
	for id in "${ids[@]}"; do
		VERIFY_ID="$id"
		wait_for "verify sandbox $id deleted" 120 verify_sandbox_gone
	done
	pass "verify sandboxes cleaned up"
}

# --- standalone entry ----------------------------------------------------------------

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
	resolve_osb
	require_template_id
	trap 'on_error verify-sandbox' ERR
	run_stage "end-to-end verify (CLI create -> gateway -> execd /ping)" opensandbox_verify
fi
