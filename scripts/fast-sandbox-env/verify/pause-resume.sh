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

# verify/pause-resume.sh — pause/resume round trip (CLI -> FastPath checkpoint)
#
# Coverage:
#
#   1. Baseline: create a sandbox via `osb sandbox create` (template,
#      skip-health-check), poll it to Running, and confirm execd /ping
#      returns 200 through a freshly resolved signed gateway route.
#   2. Pause semantics (durable-first): POST pause, then poll GET until
#      state=Paused. Paused means the checkpoint is fully durable in the
#      artifact store AND the fastlet capacity is released — not merely
#      that the call was accepted. The pause -> Paused latency is logged.
#   3. Route release (negative assertion): after Paused, the OLD signed
#      route must no longer serve /ping — the gateway must reject a
#      route whose sandbox is not running. A still-serving paused
#      sandbox fails the verify.
#   4. Resume: POST resume, poll GET back to Running (checkpoint
#      restored from the artifact store), then /ping must return 200
#      through a FRESH route — resume advances the route generation, so
#      re-resolving the endpoint is mandatory and the old route staying
#      valid would indicate a generation bug.
#   5. Cleanup: kill the sandbox and wait until GET 404s.
#
# Runs as part of `integration.sh up` (the entry chains every verify
# script) or standalone against a live stack from `env.sh up`.

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib.sh"

pause_resume_verify() {
	# Accepted + poll: Paused == checkpoint durable + capacity released;
	# resume advances the route generation, so /ping needs a fresh route.
	local created t0 t1 t2 t3
	log "verify (pause): creating a sandbox via the opensandbox CLI (templateId=$TEMPLATE_ID)"
	t0="$(now_ms)"
	created="$(osb_api sandbox create --template "$TEMPLATE_ID" --timeout 1h \
		--metadata origin=fast-sandbox-env-pause --skip-health-check -o json 2>/dev/null)" \
		|| fail "osb sandbox create failed against $SERVER_URL"
	VERIFY_ID="$(printf '%s' "$created" | jq -r '.id')"
	[[ -n "$VERIFY_ID" && "$VERIFY_ID" != "null" ]] || fail "create response carried no id"
	wait_for "pause target Running" 150 sandbox_running
	t1="$(now_ms)"
	log "verify (pause): $VERIFY_ID create->Running $(( (t1 - t0) / 1000000 ))ms"

	wait_for "pre-pause execd /ping 200 through the gateway" 100 execd_ping_ok

	log "verify (pause): osb sandbox pause $VERIFY_ID"
	osb_api sandbox pause "$VERIFY_ID" >/dev/null 2>&1 \
		|| fail "pause failed for $VERIFY_ID"
	# Paused is durable-first: the checkpoint must be complete in the artifact
	# store before the state is reported; the dump itself keeps serving.
	wait_for "poll GET until Paused (checkpoint durable, capacity released)" 240 sandbox_paused
	t2="$(now_ms)"
	log "verify (pause): $VERIFY_ID pause->Paused (checkpoint durable) $(( (t2 - t1) / 1000000 ))ms"
	if execd_ping_ok; then
		fail "paused sandbox still serves /ping through the gateway"
	fi
	pass "paused: execd /ping no longer served (runtime released, signed route rejected at the gateway)"

	log "verify (pause): osb sandbox resume $VERIFY_ID"
	t2="$(now_ms)"
	osb_api sandbox resume "$VERIFY_ID" --skip-health-check >/dev/null 2>&1 \
		|| fail "resume failed for $VERIFY_ID"
	wait_for "poll GET until Running (checkpoint restored)" 240 sandbox_running
	t3="$(now_ms)"
	log "verify (pause): $VERIFY_ID resume->Running (checkpoint restored) $(( (t3 - t2) / 1000000 ))ms"
	wait_for "post-resume execd /ping 200 through a fresh route" 100 execd_ping_ok
	pass "pause/resume round-trip timings: pause->Paused $(( (t2 - t1) / 1000000 ))ms, resume->Running $(( (t3 - t2) / 1000000 ))ms (opensandbox CLI -> FastPath -> artifact store)"

	osb_api sandbox kill "$VERIFY_ID" >/dev/null 2>&1 \
		|| log "verify cleanup: kill failed; remove $VERIFY_ID manually"
	wait_for "pause/resume sandbox deleted" 120 verify_sandbox_gone
}

# --- standalone entry ----------------------------------------------------------------

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
	resolve_osb
	require_template_id
	trap 'on_error pause-resume' ERR
	run_stage "pause/resume verify (CLI -> FastPath checkpoint)" pause_resume_verify
fi
