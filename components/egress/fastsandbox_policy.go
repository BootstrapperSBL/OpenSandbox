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
// pause checkpoint) → 409; policy persistence recovery latch → 503.
// Validation failure → 400 NACK keeping last-good. With persistence enabled
// every write runs the commit protocol — persist → apply → ack — so the ack
// means durable AND applied (see fastsandbox_policy_persist.go).
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/alibaba/opensandbox/egress/pkg/actionhandler"
	"github.com/alibaba/opensandbox/egress/pkg/constants"
	"github.com/alibaba/opensandbox/egress/pkg/log"
	"github.com/alibaba/opensandbox/egress/pkg/policy"
	"github.com/alibaba/opensandbox/egress/pkg/subject"
)

// policyEntry records the per-subject policy bookkeeping: the revision the
// relay preconditions fence on, the runtime fence the record was
// materialized under, and the two state flags. The policy itself lives in
// the registry (active subjects) or pendingPolicies (denying subjects).
type policyEntry struct {
	revision int64
	fence    subject.Fencing
	// hydrated marks a record loaded from the persisted policy file: the
	// binding input no longer drives this subject's policy — the file (and
	// the relay writes on top of it) is authoritative, exactly like the
	// vault slice. Sticky for the record's lifetime.
	hydrated bool
	// sealed marks a paused subject whose policy file was exported into the
	// snapshot bundle: every relay op answers 409; enforcement is unchanged.
	sealed bool
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
// precondition, the seal, and the recorded policy under one s.mu hold. A
// status other than zero means the caller must write (status, msg).
func (s *fastSandboxPolicyServer) selectRelayPolicy(r *http.Request, subj subject.Subject) (*policyRelayDocument, int, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fence, ok := s.reg.Fence(subj)
	if !ok {
		return nil, http.StatusNotFound, "unknown subject"
	}
	if inc := strings.TrimSpace(r.Header.Get(constants.EgressVaultIncarnationHeader)); inc != "" && inc != fence.RuntimeInstanceID {
		return nil, http.StatusPreconditionFailed, "expectedIncarnation mismatch"
	}
	if e := s.policies[subj]; e != nil && e.sealed {
		return nil, http.StatusConflict, "subject policy is sealed (paused); the bundle copy is already taken"
	}
	pol := s.reg.UserPolicy(subj)
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

	// Guards + decision under one s.mu hold, serialized against rebinds and
	// terminal purges.
	s.mu.Lock()
	fence, ok := s.reg.Fence(subj)
	if !ok {
		s.mu.Unlock()
		http.Error(w, "unknown subject", http.StatusNotFound)
		return
	}
	if inc := strings.TrimSpace(r.Header.Get(constants.EgressVaultIncarnationHeader)); inc != "" && inc != fence.RuntimeInstanceID {
		s.mu.Unlock()
		http.Error(w, "expectedIncarnation mismatch", http.StatusPreconditionFailed)
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
	state, _ := s.reg.Get(subj)
	stateActive := state == subject.StateActive
	att, attOK := s.subjAtt[subj]
	s.mu.Unlock()

	if r.Method == http.MethodDelete {
		if entry == nil {
			http.Error(w, "subject has no recorded policy", http.StatusNotFound)
			return
		}
		s.deleteRelayPolicy(w, subj, fence, att, attOK, stateActive)
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
	s.putRelayPolicy(w, r, subj, fence, pol, newRev, created, entry, stateActive)
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
// and the commit are one serialized unit). The live entry keeps its
// hydrated flag — a relay write on a file-backed record stays file-backed.
func (s *fastSandboxPolicyServer) putRelayPolicy(w http.ResponseWriter, r *http.Request, subj subject.Subject, fence subject.Fencing, pol *policy.NetworkPolicy, newRev int64, created bool, entry *policyEntry, stateActive bool) {
	raw, err := json.Marshal(pol)
	if err != nil {
		log.Errorf("subject %s: policy marshal failed: %v", subj, err)
		http.Error(w, "policy persistence failure", http.StatusInternalServerError)
		return
	}
	doc := policyRelayDocument{Revision: newRev, Policy: raw}

	apply := func() error {
		if stateActive {
			// Enforcement first: a failed apply leaves the record untouched
			// (the commit protocol rolls the file back).
			if err := s.applyPolicy(subj, pol); err != nil {
				return err
			}
		}
		s.mu.Lock()
		if !stateActive {
			s.pendingPolicies[subj] = pol
		}
		hydrated := entry != nil && entry.hydrated
		s.policies[subj] = &policyEntry{revision: newRev, fence: fence, hydrated: hydrated}
		s.mu.Unlock()
		return nil
	}

	if s.policyFiles == nil {
		// Memory-only (persistence disabled): direct commit.
		if err := apply(); err != nil {
			http.Error(w, "policy apply failure", http.StatusInternalServerError)
			return
		}
		writeJSON(w, putResponseStatus(created), doc)
		return
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

// putResponseStatus maps the committed replace onto the relay contract:
// 201 when it created the record, 200 otherwise.
func putResponseStatus(created bool) int {
	if created {
		return http.StatusCreated
	}
	return http.StatusOK
}

// deleteRelayPolicy commits the revert to deny-first: memory and file go
// together, so a restart cannot resurrect a deleted policy. The caller
// holds policyCommitMu.
func (s *fastSandboxPolicyServer) deleteRelayPolicy(w http.ResponseWriter, subj subject.Subject, fence subject.Fencing, att actionhandler.NetworkAttachment, attOK, stateActive bool) {
	apply := func() error {
		if stateActive {
			// Enforcement first: nft deny-first commits before the registry
			// state (fail-closed transition), mirroring SET_BINDING removal.
			if !attOK {
				return fmt.Errorf("subject %s has no recorded attachment for the deny-first revert", subj)
			}
			if err := s.revertToDenyFirst(subj, att); err != nil {
				return err
			}
		}
		s.mu.Lock()
		delete(s.pendingPolicies, subj)
		delete(s.policies, subj)
		s.mu.Unlock()
		return nil
	}

	if s.policyFiles == nil {
		if err := apply(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	err := s.persistPolicyCandidateLocked(
		subj,
		func(fs vaultFileStore) (policy.FileMutationState, error) {
			return fs.Delete()
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

// writePolicyRelayWriteResponse maps the committed mutation onto the relay
// contract: PUT → 200 (201 when it created), DELETE → 204.
func writePolicyRelayWriteResponse(w http.ResponseWriter, r *http.Request, revision int64, created bool) {
	if r.Method == http.MethodDelete {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, policyRelayDocument{Revision: revision, Policy: json.RawMessage("null")})
}
