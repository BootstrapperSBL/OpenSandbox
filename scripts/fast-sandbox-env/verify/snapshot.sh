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

# verify/snapshot.sh — snapshot round trip (CLI -> SandboxSnapshot CR -> restore)
#
# Coverage:
#
#   1. Snapshot create: a Running, /ping-healthy source sandbox is
#      snapshotted via `osb snapshot create`; the POST returns
#      status=Creating and the server row converges from the
#      SandboxSnapshot CR via its watcher to Ready (300s budget).
#   2. Re-entry fencing during the dump window: a second snapshot POST
#      for the same sandbox must be fenced with 409 — or, during fence
#      cache lag, accepted with 202 and then resolved to a terminal
#      phase (a stuck accepted snapshot would block all future
#      snapshots through the fence).
#   3. Source survival: once the snapshot is terminal, the pause window
#      must be released — the source sandbox is Running and /ping-200
#      again.
#   4. Repeat snapshot: a second snapshot of the same source after the
#      first is terminal must produce a distinct id and reach Ready.
#   5. Listing: `osb snapshot list --sandbox-id` must contain both
#      required snapshots (and any accepted re-entry one) as Ready.
#   6. Restore: `osb sandbox create --snapshot-id` (resource flags
#      restating the pool profile) boots the artifact set published at
#      dump time — the restored sandbox reaches Running and serves
#      execd /ping through the gateway.
#   7. Cleanup: kill the restored and source sandboxes and delete every
#      snapshot row (the server forwards per-row artifact deletion).
#
# The snapshot ids are shared through SNAPSHOT_ID / SNAPSHOT_ID2 /
# SNAPSHOT_EXTRA.
#
# Housekeeping: the artifact store is pruned at entry — stale checkpoint /
# template sets are removed, the baseline golden template set and the
# indexes pointing into it are preserved.
#
# Runs as part of `integration.sh up` (the entry chains every verify
# script) or standalone against a live stack from `env.sh up`.

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib.sh"

# The snapshot verify stage shares the created snapshot ids through
# SNAPSHOT_ID / SNAPSHOT_ID2.
SNAPSHOT_ID=""
SNAPSHOT_ID2=""
# A re-entry snapshot accepted during fence cache lag (202) is tracked here
# so its terminal outcome is asserted and it is cleaned up.
SNAPSHOT_EXTRA=""

# --- stage: snapshot (opensandbox CLI -> SandboxSnapshot CR -> restore) ----------

# Ready once the server watcher converges the row from the SandboxSnapshot
# CR (Succeeded + template index published).
snapshot_ready() { # <snapshot-id>
	[[ "$(osb_api snapshot get "$1" -o json 2>/dev/null | jq -r '.status.state // empty')" == "Ready" ]]
}

# Terminal (Ready or Failed): the pause-window fence resolves any
# accepted-but-conflicting snapshot one way or the other.
snapshot_terminal() { # <snapshot-id>
	local state
	state="$(osb_api snapshot get "$1" -o json 2>/dev/null | jq -r '.status.state // empty')"
	[[ "$state" == "Ready" || "$state" == "Failed" ]]
}

snapshot_verify() {
	# Full round trip on the live stack: snapshot a Running sandbox, watch it
	# to Ready, restore a NEW sandbox from the snapshotId and boot it. Also
	# covers re-entry fencing, source-sandbox survival, and a repeat snapshot.
	local created out source_id snapshot_id snapshot_id2 restore_id reentry_out reentry_code
	# Snapshot sets are multi-GiB: drop stale ones from earlier runs before
	# this verify adds its own (baseline template kept).
	prune_artifact_store
	local t0 t1 t2 t3 t4
	t0="$(now_ms)"
	log "verify (snapshot): creating the source sandbox via the opensandbox CLI (templateId=$TEMPLATE_ID)"
	created="$(osb_api sandbox create --template "$TEMPLATE_ID" --timeout 1h \
		--metadata origin=fast-sandbox-env-snapshot --skip-health-check -o json 2>/dev/null)" \
		|| fail "osb sandbox create failed against $SERVER_URL"
	source_id="$(printf '%s' "$created" | jq -r '.id')"
	[[ -n "$source_id" && "$source_id" != "null" ]] || fail "create response carried no id"
	VERIFY_ID="$source_id"
	wait_for "snapshot source sandbox Running" 300 sandbox_running
	wait_for "pre-snapshot execd /ping 200 through the gateway" 100 execd_ping_ok
	t1="$(now_ms)"
	log "verify (snapshot): source sandbox $source_id create->Running $(( (t1 - t0) / 1000000 ))ms"

	# 1. Snapshot create returns Creating; the row converges from the
	# SandboxSnapshot CR via the server watcher.
	log "verify (snapshot): osb snapshot create $source_id --name env-verify"
	t1="$(now_ms)"
	out="$(osb_api snapshot create "$source_id" --name env-verify -o json 2>/dev/null)" \
		|| fail "snapshot create failed for $source_id"
	SNAPSHOT_ID="$(printf '%s' "$out" | jq -r '.id')"
	[[ -n "$SNAPSHOT_ID" && "$SNAPSHOT_ID" != "null" ]] || fail "snapshot create carried no id"
	[[ "$(printf '%s' "$out" | jq -r '.status')" == "Creating" ]] \
		|| fail "snapshot create did not return Creating: $(printf '%s' "$out" | head -c 300)"

	# 2. Re-entry during the dump window: FastPath fences with 409 once the
	# CR is cache-visible; with cache lag it is accepted (202) and the
	# pause window resolves it to a terminal phase later.
	reentry_out="$(curl -sS -m 60 -w '\n%{http_code}' -X POST \
		-H "OPEN-SANDBOX-API-KEY: $SERVER_API_KEY" -H "Content-Type: application/json" \
		-d '{"name":"env-verify-reentry"}' "$SERVER_URL/sandboxes/$source_id/snapshots" 2>/dev/null || true)"
	reentry_code="$(printf '%s' "$reentry_out" | tail -n1)"
	reentry_out="$(printf '%s' "$reentry_out" | sed '$d')"
	case "$reentry_code" in
		409)
			pass "snapshot: re-entry rejected by the fence (409)"
			;;
		202)
			SNAPSHOT_EXTRA="$(printf '%s' "$reentry_out" | jq -r '.id' 2>/dev/null || true)"
			[[ -n "$SNAPSHOT_EXTRA" && "$SNAPSHOT_EXTRA" != "null" ]] \
				|| fail "re-entry snapshot POST returned 202 without an id: $(printf '%s' "$reentry_out" | head -c 300)"
			log "verify (snapshot): re-entry accepted during fence cache lag ($SNAPSHOT_EXTRA); terminal outcome asserted below"
			;;
		*)
			fail "re-entry snapshot POST returned unexpected HTTP ${reentry_code:-none}: $(printf '%s' "$reentry_out" | head -c 300)"
			;;
	esac

	wait_for "poll osb snapshot get $SNAPSHOT_ID until Ready (watcher -> SandboxSnapshot CR -> store index)" 300 snapshot_ready "$SNAPSHOT_ID"
	t2="$(now_ms)"
	log "verify (snapshot): $SNAPSHOT_ID snapshot create->Ready $(( (t2 - t1) / 1000000 ))ms"
	pass "snapshot: create -> Creating -> watcher -> Ready"

	# 3. Source survival: Running + /ping again after the terminal phase.
	VERIFY_ID="$source_id"
	wait_for "source sandbox Running again after the snapshot" 120 sandbox_running
	wait_for "source sandbox execd /ping 200 after the snapshot" 100 execd_ping_ok
	pass "snapshot: source sandbox survived (Running + /ping 200)"

	# 3b. An accepted re-entry snapshot must reach a terminal phase; a stuck
	# one would block all future snapshots via the re-entry fence.
	if [[ -n "$SNAPSHOT_EXTRA" ]]; then
		wait_for "re-entry snapshot $SNAPSHOT_EXTRA reaches a terminal phase" 150 snapshot_terminal "$SNAPSHOT_EXTRA"
		log "verify (snapshot): re-entry snapshot $SNAPSHOT_EXTRA terminal: $(osb_api snapshot get "$SNAPSHOT_EXTRA" -o json 2>/dev/null | jq -r '.status.state')"
		pass "snapshot: accepted re-entry snapshot resolved to a terminal phase"
	fi

	# 4. Second snapshot once the first is terminal: fresh id.
	t3="$(now_ms)"
	out="$(osb_api snapshot create "$source_id" --name env-verify-2 -o json 2>/dev/null)" \
		|| fail "second snapshot create failed for $source_id"
	snapshot_id2="$(printf '%s' "$out" | jq -r '.id')"
	[[ -n "$snapshot_id2" && "$snapshot_id2" != "null" && "$snapshot_id2" != "$SNAPSHOT_ID" ]] \
		|| fail "second snapshot did not produce a distinct id: $snapshot_id2"
	SNAPSHOT_ID2="$snapshot_id2"
	wait_for "poll osb snapshot get $snapshot_id2 until Ready" 300 snapshot_ready "$snapshot_id2"
	t4="$(now_ms)"
	log "verify (snapshot): $snapshot_id2 second snapshot create->Ready $(( (t4 - t3) / 1000000 ))ms"
	pass "snapshot: repeated snapshot of the same sandbox -> Ready (distinct id)"

	# 5. Listing: sandboxId scoping returns both required snapshots, both
	# Ready (an accepted re-entry snapshot may add a third, terminal row).
	out="$(osb_api snapshot list --sandbox-id "$source_id" --page-size 50 -o json 2>"$WORK/last-snapshot-list.err")" \
		|| fail "snapshot list failed for $source_id: $(head -c 400 "$WORK/last-snapshot-list.err" 2>/dev/null)"
	[[ "$(printf '%s' "$out" | jq -r --arg id "$SNAPSHOT_ID" --arg id2 "$snapshot_id2" \
		'[.items[] | select((.id == $id or .id == $id2) and .status.state == "Ready")] | length')" == "2" ]] \
		|| fail "snapshot list does not contain both required snapshots as Ready: $(printf '%s' "$out" | head -c 400)"
	if [[ -n "$SNAPSHOT_EXTRA" ]]; then
		[[ "$(printf '%s' "$out" | jq -r --arg id "$SNAPSHOT_EXTRA" \
			'[.items[] | select(.id == $id)] | length')" == "1" ]] \
			|| fail "accepted re-entry snapshot $SNAPSHOT_EXTRA missing from the list"
	fi
	pass "snapshot: list scoped by sandboxId contains the snapshots (Ready)"

	# 6. Restore: the row resolves to the published template index key; the
	# resource flags restate the pool profile (firecracker pool).
	local restored
	log "verify (snapshot): osb sandbox create --snapshot-id $SNAPSHOT_ID (pool profile restated)"
	t3="$(now_ms)"
	restored="$(osb_api sandbox create --snapshot-id "$SNAPSHOT_ID" --timeout 1h \
		--resource cpu=1 --resource memory=512Mi --resource pids=128 \
		--skip-health-check -o json 2>/dev/null)" \
		|| fail "osb sandbox create (snapshotId=$SNAPSHOT_ID) failed"
	restore_id="$(printf '%s' "$restored" | jq -r '.id')"
	[[ -n "$restore_id" && "$restore_id" != "null" ]] || fail "restore create carried no id"
	VERIFY_ID="$restore_id"
	wait_for "restored sandbox Running" 600 sandbox_running
	t4="$(now_ms)"
	wait_for "restored execd /ping 200 through the gateway" 300 execd_ping_ok
	log "verify (snapshot): restored $restore_id create->Running $(( (t4 - t3) / 1000000 ))ms"
	pass "snapshot: restore -> sandbox boots the published artifact set -> execd /ping OK"

	# 7. Cleanup; the server forwards artifact deletion per snapshot row.
	osb_api sandbox kill "$restore_id" >/dev/null 2>&1 \
		|| log "verify cleanup: kill $restore_id failed"
	wait_for "restored sandbox deleted" 120 verify_sandbox_gone
	VERIFY_ID="$source_id"
	osb_api sandbox kill "$source_id" >/dev/null 2>&1 \
		|| log "verify cleanup: kill $source_id failed"
	wait_for "snapshot source sandbox deleted" 120 verify_sandbox_gone
	for snapshot_id in "$SNAPSHOT_ID" "$SNAPSHOT_ID2" "$SNAPSHOT_EXTRA"; do
		[[ -n "$snapshot_id" ]] || continue
		osb_api snapshot delete "$snapshot_id" >/dev/null 2>&1 \
			|| log "verify cleanup: snapshot delete $snapshot_id failed"
	done
	pass "snapshot: cleanup (restored + source sandboxes, both snapshot rows)"
}

# --- standalone entry ----------------------------------------------------------------

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
	resolve_osb
	require_template_id
	trap 'on_error snapshot-verify' ERR
	run_stage "snapshot verify (CLI -> SandboxSnapshot -> restore)" snapshot_verify
fi
