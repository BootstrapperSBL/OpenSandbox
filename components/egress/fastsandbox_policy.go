// Copyright 2026 The OpenSandbox Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Relay policy surface: /policy/{sandboxUid} terminates the FastPath
// handler-relay (server → FastPath → Fastlet → this loopback listener) for
// the subject's recorded egress policy — the runtime twin of the vault relay
// (fastsandbox_vault.go). The binding input seeds the policy at create; the
// relay owns every runtime mutation, and the mutation is authoritative over
// later binding replays (see rehydratePolicyReload).
//
// Surface: GET the recorded policy with its revision, PUT a full replace
// with an optional expectedRevision (412 on mismatch, creates when absent),
// DELETE reverting the subject to deny-first. POST/PATCH are deliberately
// absent: creation is unconditional PUT, and a patch composes server-side
// (relay GET → merge → relay PUT), mirroring the vault relay.
//
// Sidecar-parity guards on every op: unregistered subject → 404, never
// cached; expectedIncarnation mismatch → 412; sealed (exported for a
// pause checkpoint) → 409; policy persistence recovery latch → 503 on
// writes (GET keeps serving the in-memory record). Validation failure →
// 400 NACK keeping last-good. With persistence enabled
// every write runs the commit protocol — persist → apply → ack — so the ack
// means durable AND applied (see fastsandbox_policy_persist.go).
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/alibaba/opensandbox/egress/pkg/constants"
	"github.com/alibaba/opensandbox/egress/pkg/log"
	"github.com/alibaba/opensandbox/egress/pkg/policy"
	"github.com/alibaba/opensandbox/egress/pkg/subject"
)

// policyEntry records the per-subject policy bookkeeping: the revision the
// relay preconditions fence on, the runtime fence the record was
// materialized under, and the sealed flag. The policy itself lives in the
// registry (active subjects) or pendingPolicies (denying subjects). A
// record is authoritative once it exists: the binding input only ever
// seeds a fresh subject, and every later policy change goes through the
// relay or the snapshot transfer — exactly like the vault.
type policyEntry struct {
	revision int64
	fence    subject.Fencing
	// sealed marks a paused subject whose policy file was exported into the
	// snapshot bundle: every relay op answers 409; enforcement is unchanged.
	sealed bool
	// degraded is non-empty while the persisted policy could not be
	// reloaded: the record stays default-deny (fail closed) until a
	// successful relay write heals it.
	degraded string
}

// policyRelayDocument is the GET response and PUT body of the relay
// surface. Revision is echoed by GET and acts as the PUT precondition (the
// GET body is re-pushable verbatim); ExpectedRevision is the explicit
// precondition form. Both present must agree.
type policyRelayDocument struct {
	Revision         int64           `json:"revision"`
	ExpectedRevision *int64          `json:"expectedRevision,omitempty"`
	Policy           json.RawMessage `json:"policy"`
}

// maxPolicyRelayBodyBytes bounds one relay body: the policy (the platform
// binding-input cap) plus the document framing.
const maxPolicyRelayBodyBytes = policy.MaxPolicyBodyBytes + 1<<10

// handlePolicyRelay serves /policy/{sandboxUid} for all relay verbs.
func (s *fastSandboxPolicyServer) handlePolicyRelay(w http.ResponseWriter, r *http.Request) {
	uid := strings.TrimPrefix(r.URL.Path, constants.PolicyRelayPathPrefix)
	if !validVaultSubjectID(uid) {
		http.Error(w, "missing or invalid sandbox uid in path", http.StatusBadRequest)
		return
	}
	subj := subject.FromSandboxUID(uid)
	switch r.Method {
	case http.MethodGet:
		doc, status, msg := s.selectRelayPolicy(r, subj)
		if status != 0 {
			http.Error(w, msg, status)
			return
		}
		writeJSON(w, http.StatusOK, doc)
	case http.MethodPut, http.MethodDelete:
		s.handlePolicyRelayWrite(w, r, subj)
	default:
		w.Header().Set("Allow", "GET, PUT, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// selectRelayPolicy decides registration, the expectedIncarnation
// precondition, the seal, and the recorded policy. Registry reads happen
// BEFORE s.mu — the lock order is registry → s.mu everywhere (the takeover
// path holds the registry write lock while purging subject state under
// s.mu; the reverse order deadlocks the DNS hot path). A fence change
// between the read and the lock is bounded: the purge removes the record,
// and the write paths re-validate the fence at commit time.
func (s *fastSandboxPolicyServer) selectRelayPolicy(r *http.Request, subj subject.Subject) (*policyRelayDocument, int, string) {
	fence, ok := s.reg.Fence(subj)
	if !ok {
		return nil, http.StatusNotFound, "unknown subject"
	}
	if inc := strings.TrimSpace(r.Header.Get(constants.EgressVaultIncarnationHeader)); inc != "" && inc != fence.RuntimeInstanceID {
		return nil, http.StatusPreconditionFailed, "expectedIncarnation mismatch"
	}
	pol := s.reg.UserPolicy(subj)
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.fenceMatchesLocked(subj, fence) {
		return nil, http.StatusNotFound, "unknown subject"
	}
	if e := s.policies[subj]; e != nil && e.sealed {
		return nil, http.StatusConflict, "subject policy is sealed (paused); the bundle copy is already taken"
	}
	if pol == nil {
		pol = s.pendingPolicies[subj]
	}
	if pol == nil {
		return nil, http.StatusNotFound, "subject has no recorded policy"
	}
	rev := int64(0)
	if e := s.policies[subj]; e != nil {
		rev = e.revision
	}
	raw, err := json.Marshal(pol)
	if err != nil {
		return nil, http.StatusInternalServerError, "policy serialization failure"
	}
	return &policyRelayDocument{Revision: rev, Policy: raw}, 0, ""
}

// handlePolicyRelayWrite serves PUT (full replace, create-when-absent) and
// DELETE (revert to deny-first).
//
// The body is parsed and the policy validated BEFORE the commit serialization
// is taken: a stalled or invalid client must never hold it. Guards run under
// s.mu; the commit protocol itself serializes per process on
// policyCommitMu (the Fastlet serializes same-UID actions, but relayed
// writers from server replicas do not serialize with each other), and the
// apply closures take s.mu only for the bookkeeping maps — never around
// enforcement, which takes the registry write lock.
func (s *fastSandboxPolicyServer) handlePolicyRelayWrite(w http.ResponseWriter, r *http.Request, subj subject.Subject) {
	var doc policyRelayDocument
	if r.Method == http.MethodPut {
		data, err := io.ReadAll(io.LimitReader(r.Body, maxPolicyRelayBodyBytes+1))
		if err != nil {
			http.Error(w, "failed to read policy body: "+err.Error(), http.StatusBadRequest)
			return
		}
		if len(data) > maxPolicyRelayBodyBytes {
			http.Error(w, fmt.Sprintf("policy body exceeds %d bytes", maxPolicyRelayBodyBytes), http.StatusBadRequest)
			return
		}
		dec := json.NewDecoder(strings.NewReader(string(data)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&doc); err != nil {
			http.Error(w, "invalid policy replace request: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	// The body has been consumed; a late response must not try to read it.
	r.Body.Close()

	if r.Method == http.MethodPut && len(doc.Policy) == 0 {
		http.Error(w, "policy body required", http.StatusBadRequest)
		return
	}
	pol, err := policy.ParsePolicy(string(doc.Policy))
	if err != nil {
		http.Error(w, "invalid policy: "+err.Error(), http.StatusBadRequest)
		return
	}
	expected, perr := relayPolicyPrecondition(&doc)
	if perr != nil {
		http.Error(w, perr.Error(), http.StatusBadRequest)
		return
	}

	// Serialize the whole write — guards, decision, and commit — per
	// process on policyCommitMu: the Fastlet serializes same-UID actions,
	// but relayed writers from server replicas do not serialize with each
	// other or with a concurrent SET_BINDING commit. The decision must be
	// commit-atomic or two racing replaces could land the same revision.
	// The ordering policyCommitMu → s.mu is the commit path's; enforcement
	// in the apply closures never runs under s.mu.
	s.policyCommitMu.Lock()
	defer s.policyCommitMu.Unlock()

	// Registry reads before s.mu (lock order: registry → s.mu, see
	// selectRelayPolicy); the commit-time target re-check closes the TOCTOU.
	fence, ok := s.reg.Fence(subj)
	if !ok {
		http.Error(w, "unknown subject", http.StatusNotFound)
		return
	}
	if inc := strings.TrimSpace(r.Header.Get(constants.EgressVaultIncarnationHeader)); inc != "" && inc != fence.RuntimeInstanceID {
		http.Error(w, "expectedIncarnation mismatch", http.StatusPreconditionFailed)
		return
	}
	// Guards + decision under one s.mu hold, serialized against rebinds and
	// terminal purges (the whole write already holds policyCommitMu).
	s.mu.Lock()
	if !s.fenceMatchesLocked(subj, fence) {
		s.mu.Unlock()
		http.Error(w, "unknown subject", http.StatusNotFound)
		return
	}
	entry := s.policies[subj]
	if entry != nil && entry.sealed {
		s.mu.Unlock()
		http.Error(w, "subject policy is sealed (paused); the bundle copy is already taken", http.StatusConflict)
		return
	}
	if recovery := s.policyRecovery.Load(); recovery != nil {
		s.mu.Unlock()
		http.Error(w, "policy persistence recovery required: "+recovery.reason, http.StatusServiceUnavailable)
		return
	}
	cur := int64(0)
	if entry != nil {
		cur = entry.revision
	}
	s.mu.Unlock()

	if r.Method == http.MethodDelete {
		if entry == nil {
			http.Error(w, "subject has no recorded policy", http.StatusNotFound)
			return
		}
		// Deletion is an authoritative tombstone at the successor revision.
		s.deleteRelayPolicy(w, subj, fence, cur+1)
		return
	}

	// PUT: a conditional replace against an absent record is a 412, not a
	// create (sidecar parity).
	if expected != nil && entry == nil {
		http.Error(w, "expectedRevision mismatch", http.StatusPreconditionFailed)
		return
	}
	if expected != nil && *expected != cur {
		http.Error(w, "expectedRevision mismatch", http.StatusPreconditionFailed)
		return
	}
	created := entry == nil
	newRev := cur + 1
	s.putRelayPolicy(w, r, subj, fence, pol, newRev, created)
}

// relayPolicyPrecondition extracts the effective precondition. The revision
// echoed by GET and an explicit expectedRevision must agree when both are
// present (ambiguous request).
func relayPolicyPrecondition(doc *policyRelayDocument) (expected *int64, err error) {
	switch {
	case doc.ExpectedRevision == nil:
		if doc.Revision != 0 {
			rev := doc.Revision
			expected = &rev
		}
	case doc.Revision == 0 || doc.Revision == *doc.ExpectedRevision:
		expected = doc.ExpectedRevision
	default:
		err = fmt.Errorf("revision %d and expectedRevision %d disagree", doc.Revision, *doc.ExpectedRevision)
	}
	return expected, err
}

// putRelayPolicy commits a full replace: persist → apply → ack, so the ack
// means durable AND applied. The caller holds policyCommitMu (the decision
// and the commit are one serialized unit, and the data-plane-ready hook
// serializes on the same mutex). The apply closure re-reads the lifecycle
// state and the registration fence — both can change between the guard
// phase and this commit (a concurrent hook activation, a rebind) — so the
// recorded state can never diverge from what was actually enforced.
func (s *fastSandboxPolicyServer) putRelayPolicy(w http.ResponseWriter, r *http.Request, subj subject.Subject, fence subject.Fencing, pol *policy.NetworkPolicy, newRev int64, created bool) {
	raw, err := json.Marshal(pol)
	if err != nil {
		log.Errorf("subject %s: policy marshal failed: %v", subj, err)
		http.Error(w, "policy persistence failure", http.StatusInternalServerError)
		return
	}
	doc := policyRelayDocument{Revision: newRev, Policy: raw}

	apply := func() error {
		state, err := s.policyCommitTarget(subj, fence)
		if err != nil {
			return err
		}
		if state == subject.StateActive {
			// Enforcement first: a failed apply leaves the record untouched
			// (the commit protocol rolls the file back).
			if err := s.applyPolicy(subj, pol); err != nil {
				return err
			}
		}
		s.mu.Lock()
		if state != subject.StateActive {
			s.pendingPolicies[subj] = pol
		}
		// A fresh entry also clears a degraded mark: the successful write
		// IS the heal.
		s.policies[subj] = &policyEntry{revision: newRev, fence: fence}
		s.mu.Unlock()
		return nil
	}

	payload, err := policy.EncodePolicyFile(fence.RuntimeInstanceID, fence.AttachmentID, newRev, raw)
	if err != nil {
		log.Errorf("subject %s: policy file encode failed: %v", subj, err)
		http.Error(w, "policy persistence failure", http.StatusInternalServerError)
		return
	}
	err = s.persistPolicyCandidateLocked(
		subj,
		func(fs vaultFileStore) (policy.FileMutationState, error) {
			return fs.SaveRaw(payload)
		},
		apply,
	)
	if err != nil {
		// Uncertain persist latched → 503; every other failure kept last-good
		// on both sides → retryable 500. Details stay in the log.
		log.Errorf("subject %s: policy relay write failed: %v", subj, err)
		status := http.StatusInternalServerError
		if recovery := s.policyRecovery.Load(); recovery != nil {
			status = http.StatusServiceUnavailable
		}
		http.Error(w, "policy persistence failure", status)
		return
	}
	writeJSON(w, putResponseStatus(created), doc)
}

// policyCommitTarget re-reads the subject's lifecycle state and verifies
// the registration fence still matches the commit's — the data-plane-ready
// activation and rebinds run outside the commit serialization, so a stale
// apply must be aborted (the commit protocol rolls the file back) instead
// of landing on the wrong identity or state. Registry reads only: no s.mu
// (lock order: registry → s.mu, see selectRelayPolicy).
func (s *fastSandboxPolicyServer) policyCommitTarget(subj subject.Subject, fence subject.Fencing) (subject.State, error) {
	regFence, ok := s.reg.Fence(subj)
	if !ok || regFence != fence {
		return subject.StateAbsent, fmt.Errorf("stale policy commit (fence changed) for subject %s", subj)
	}
	state, _ := s.reg.Get(subj)
	return state, nil
}

// putResponseStatus maps the committed replace onto the relay contract:
// 201 when it created the record, 200 otherwise.
func putResponseStatus(created bool) int {
	if created {
		return http.StatusCreated
	}
	return http.StatusOK
}

// deleteRelayPolicy commits the deletion as an authoritative default-deny
// tombstone: the record persists at the successor revision (memory + file)
// and enforcement becomes default-deny — in place on an active subject
// (which stays active, so a later relay PUT re-enables immediately), held
// pending on a denying one. An egress restart reloads the tombstone
// instead of letting the replayed bootstrap binding resurrect the deleted
// policy. GET serves the deny record. The caller holds policyCommitMu.
func (s *fastSandboxPolicyServer) deleteRelayPolicy(w http.ResponseWriter, subj subject.Subject, fence subject.Fencing, newRev int64) {
	deny := policy.DefaultDenyPolicy()
	apply := func() error {
		state, err := s.policyCommitTarget(subj, fence)
		if err != nil {
			return err
		}
		if state == subject.StateActive {
			// Enforcement first: the deny tombstone applies IN PLACE — the
			// subject stays active with default-deny enforced (the operator
			// always overlay keeps applying), so a later relay PUT
			// re-enables traffic immediately; the generic handler relay
			// never replays a data-plane-ready hook to activate a
			// pending-only replacement. nft commits before the registry
			// state (fail-closed transition).
			if err := s.applyPolicy(subj, deny); err != nil {
				return err
			}
		}
		s.mu.Lock()
		// The activation barrier keeps working across a hook replay: a
		// replayed data-plane-ready activates the deny record, never a
		// stale policy. On an active subject the pending deny is
		// idempotent with what was just enforced.
		s.pendingPolicies[subj] = deny
		s.policies[subj] = &policyEntry{revision: newRev, fence: fence}
		s.mu.Unlock()
		return nil
	}

	raw, err := json.Marshal(deny)
	if err != nil {
		http.Error(w, "policy persistence failure", http.StatusInternalServerError)
		return
	}
	payload, err := policy.EncodePolicyFile(fence.RuntimeInstanceID, fence.AttachmentID, newRev, raw)
	if err != nil {
		http.Error(w, "policy persistence failure", http.StatusInternalServerError)
		return
	}
	err = s.persistPolicyCandidateLocked(
		subj,
		func(fs vaultFileStore) (policy.FileMutationState, error) {
			return fs.SaveRaw(payload)
		},
		apply,
	)
	if err != nil {
		log.Errorf("subject %s: policy relay delete failed: %v", subj, err)
		status := http.StatusInternalServerError
		if recovery := s.policyRecovery.Load(); recovery != nil {
			status = http.StatusServiceUnavailable
		}
		http.Error(w, "policy persistence failure", status)
		return
	}
	log.Infof("subject %s: policy deleted (deny-first), record purged", subj)
	w.WriteHeader(http.StatusNoContent)
}
