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

// Policy snapshot transfer across pause/resume, mirroring the vault snapshot
// transfer (fastsandbox_vault_snapshot.go). POLICY_EXPORT copies the
// subject's recorded policy file into the snapshot bundle strictly before the
// runtime teardown and seals the subject; POLICY_IMPORT lands the bundle
// file re-stamped with the restored fence — the only authorized incarnation
// transfer — through the same commit protocol as the relay writes, marking
// the recorded policy so later binding replays never override it. The
// invocation side (driver/Fastlet hooks, snapshot manifest) is platform
// work in the fast-sandbox repository.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"strings"

	"github.com/alibaba/opensandbox/egress/pkg/actionhandler"
	"github.com/alibaba/opensandbox/egress/pkg/log"
	"github.com/alibaba/opensandbox/egress/pkg/policy"
	"github.com/alibaba/opensandbox/egress/pkg/subject"
)

// maxPolicySnapshotBytes bounds a bundle read: the largest valid policy file
// is a max relay body plus the encoded envelope — anything over this is not
// a v1 policy file.
const maxPolicySnapshotBytes = policy.MaxEncodedPolicyFileBytes

var errPolicySnapshotTooLarge = fmt.Errorf("policy bundle file exceeds %d bytes", maxPolicySnapshotBytes)

// applyPolicyExport copies the subject's recorded policy file into the bundle
// target and marks the subject sealed. A subject without a policy file just
// seals. Any failure leaves the subject unsealed and its enforcement
// unchanged; what the pause flow does with that is the caller's call — the
// fast-sandbox driver fails the pause checkpoint, so the teardown never runs
// without a bundle. A retried export re-copies idempotently (while sealed no
// relay op can change the source).
//
// Three phases: guards + a consistent source image under s.mu, the
// driver-owned copy without the lock (it may be slow; every action and relay
// op goes through s.mu), then a re-check under the lock — sealed only if the
// source is still the exact copied image, else 409. The recovery latch
// rejects the export in both guarded phases: with on-disk state unconfirmed,
// the copy plus the teardown purge would make uncertain bytes the only
// surviving recorded policy.
func (s *fastSandboxPolicyServer) applyPolicyExport(env *actionhandler.Envelope) (int, error) {
	if s.policyFiles == nil {
		return http.StatusInternalServerError, errors.New("policy export requires policy persistence (OPENSANDBOX_EGRESS_POLICY_DIR)")
	}
	subj := subject.FromSandboxUID(env.Sandbox.UID)
	fence := subject.FromRevision(env)
	target := strings.TrimSpace(env.Snapshot.Path)
	if s.reservesStatePath(target) {
		return http.StatusBadRequest, fmt.Errorf("policy bundle target %q must not live under a per-subject state directory", target)
	}
	// A subject that never registered (a sandbox created without an egress
	// binding, or after terminal cleanup) has no policy to carry: 200 so the
	// checkpoint proceeds — a 404 would fail every pause of a binding-less
	// sandbox. A registered subject under a stale fence still fails below.
	// Registry reads before the lock acquisitions (lock order: registry →
	// policyCommitMu → s.mu, see selectRelayPolicy).
	regFence, registered := s.reg.Fence(subj)
	if !registered {
		log.Infof("policy export: subject %s not registered; no policy to carry, checkpoint proceeds without it", subj)
		return http.StatusOK, nil
	}

	// Phase 1: guards + consistent source image, serialized with the policy
	// relay commits (policyCommitMu). A relay writer that passed its guards
	// but has not committed yet is either flushed before the snapshot (the
	// copy carries its write) or blocked until phase 3 — it can never
	// commit "under" the seal.
	s.policyCommitMu.Lock()
	s.mu.Lock()
	snap, status, err := s.policyExportSourceImageLocked(subj, fence, regFence, registered)
	s.mu.Unlock()
	s.policyCommitMu.Unlock()
	if err != nil {
		return status, err
	}

	// Phase 2: no lock held across the driver-owned write. A relay commit
	// here is caught by the phase-3 re-check (the copied image no longer
	// matches the live file → 409, no seal).
	if snap.Exists() {
		bundle, err := s.policyFiles.newFile(target)
		if err != nil {
			return http.StatusInternalServerError, fmt.Errorf("policy bundle target unavailable: %w", err)
		}
		state, err := bundle.SaveRaw(snap.Data())
		if err != nil || state != policy.FileCommitted {
			return http.StatusInternalServerError, fmt.Errorf("policy bundle copy failed (state %v): %v", state, err)
		}
	}

	// Phase 3: seal only against the exact copied image, again serialized
	// with the relay commits — between the re-check and the seal no writer
	// can pass the guards (they now observe the seal) or commit. The fence
	// is re-read fresh (registry before s.mu) so a rebind during the copy
	// fails the export instead of sealing the wrong subject's bytes.
	regFence, registered = s.reg.Fence(subj)
	s.policyCommitMu.Lock()
	defer s.policyCommitMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	live, status, err := s.policyExportSourceImageLocked(subj, fence, regFence, registered)
	if err != nil {
		return status, err
	}
	if live.Exists() != snap.Exists() || (snap.Exists() && !bytes.Equal(live.Data(), snap.Data())) {
		return http.StatusConflict, fmt.Errorf("policy file changed during export for subject %s; bundle copy not sealed", subj)
	}
	if !snap.Exists() {
		// Nothing to carry: a previous attempt may have left stale bytes at
		// the target — remove them, or a later import would restore a policy
		// deleted during the pause.
		bundle, err := s.policyFiles.newFile(target)
		if err != nil {
			return http.StatusInternalServerError, fmt.Errorf("policy bundle target unavailable: %w", err)
		}
		state, err := bundle.Delete()
		if err != nil || (state != policy.FileCommitted && state != policy.FileUnchanged) {
			return http.StatusInternalServerError, fmt.Errorf("policy bundle removal failed (state %v): %v", state, err)
		}
	}
	// Durable seal first: a restart before REMOVE_BINDING must reload the
	// entry sealed, or relay writes would stale the taken bundle.
	if err := s.policyFiles.seal(subj); err != nil {
		return http.StatusInternalServerError, fmt.Errorf("policy seal marker: %w", err)
	}
	e := s.policies[subj]
	if e == nil || e.fence != fence {
		e = &policyEntry{fence: fence}
	}
	e.sealed = true
	s.policies[subj] = e
	if snap.Exists() {
		log.Infof("subject %s: policy exported to snapshot bundle, subject sealed", subj)
	} else {
		log.Infof("subject %s: no policy file to export, subject sealed", subj)
	}
	return http.StatusOK, nil
}

// policyExportSourceImageLocked runs the export guards and returns a
// consistent image of the subject's policy file. regFence/registered are
// the caller's pre-read of the registration (lock order: registry →
// policyCommitMu → s.mu, see applyPolicyExport). Callers hold s.mu.
func (s *fastSandboxPolicyServer) policyExportSourceImageLocked(subj subject.Subject, fence subject.Fencing, regFence subject.Fencing, registered bool) (*policy.PolicyFileSnapshot, int, error) {
	if !registered {
		return nil, http.StatusNotFound, fmt.Errorf("policy export for unknown subject %s", subj)
	}
	if !regFence.Matches(fence) {
		return nil, http.StatusConflict, fmt.Errorf("stale policy export (fence mismatch) for subject %s", subj)
	}
	if recovery := s.policyRecovery.Load(); recovery != nil {
		return nil, http.StatusServiceUnavailable, fmt.Errorf("policy persistence recovery required: %s", recovery.reason)
	}
	fs, err := s.policyFiles.storeFor(subj)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("policy file store unavailable: %w", err)
	}
	snap, err := fs.Snapshot()
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("policy file snapshot: %w", err)
	}
	if snap.Exists() {
		// Carry only bytes attributable to the registered fence: a leftover
		// from a previous incarnation (purge failed), a corrupt file, or a
		// newer schema is treated as absent — never exported, or import
		// would re-stamp a foreign policy as current.
		pf, _, decErr := policy.DecodePolicyFile(snap.Data())
		if decErr != nil || pf.Incarnation != regFence.RuntimeInstanceID || pf.AttachmentID != regFence.AttachmentID {
			what := "unattributable fence"
			if errors.Is(decErr, policy.ErrUnsupportedPolicyFileVersion) {
				what = "newer schema"
			} else if decErr != nil {
				what = "unreadable"
			}
			log.Infof("subject %s: policy file not carried (%s)", subj, what)
			return policy.NewFileSnapshot("", nil, false), 0, nil
		}
	}
	return snap, 0, nil
}

// applyPolicyImport lands the bundle file as the subject's policy file,
// re-stamped with the restored fence from the envelope (restore may land on
// any Pod, so the recorded incarnation is replaced, not compared). The file
// goes through the commit protocol and the record materializes from the bundle;
// the policy activates at the same data-plane-ready barrier as the vault.
//
// The bundle is read, decoded, and parsed before the commit serialization.
// Delivery is at-least-once: a local revision newer than the bundle acks
// idempotently — relay writes after the first import are never rolled back.
// Unregistered (before SET_BINDING), only the file lands and the
// registration-time reload validates it; registered under the envelope
// fence, the policy installs into the live record and a rejected bundle is
// a 400 with last-good kept.
func (s *fastSandboxPolicyServer) applyPolicyImport(env *actionhandler.Envelope) (int, error) {
	if s.policyFiles == nil {
		return http.StatusInternalServerError, errors.New("policy import requires policy persistence (OPENSANDBOX_EGRESS_POLICY_DIR)")
	}
	subj := subject.FromSandboxUID(env.Sandbox.UID)
	fence := subject.FromRevision(env)
	source := strings.TrimSpace(env.Snapshot.Path)
	if s.reservesStatePath(source) {
		return http.StatusBadRequest, fmt.Errorf("policy bundle source %q must not live under a per-subject state directory", source)
	}

	// Read before locking; a missing/oversized/unreadable source is
	// permanent — the fastlet retry cannot repair it.
	data, err := readPolicyBundle(source)
	if errors.Is(err, fs.ErrNotExist) {
		return http.StatusNotFound, fmt.Errorf("policy bundle file %q does not exist", source)
	}
	if errors.Is(err, errPolicySnapshotTooLarge) {
		return http.StatusBadRequest, err
	}
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("policy bundle read failed: %w", err)
	}
	pf, body, err := policy.DecodePolicyFile(data)
	if err != nil {
		return http.StatusBadRequest, fmt.Errorf("invalid policy bundle file: %v", err)
	}
	pol, parseErr := policy.ParsePolicy(string(body))
	if parseErr != nil {
		return http.StatusBadRequest, fmt.Errorf("invalid policy bundle content: %v", parseErr)
	}
	// The authorized incarnation transfer.
	payload, err := policy.EncodePolicyFile(fence.RuntimeInstanceID, fence.AttachmentID, pf.Revision, body)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("policy bundle re-stamp failed: %w", err)
	}

	// Serialize the commit against relay writes; guards run under s.mu
	// inside (the ordering policyCommitMu → s.mu is the commit path's).
	s.policyCommitMu.Lock()
	defer s.policyCommitMu.Unlock()

	// Registry reads before s.mu (lock order: registry → policyCommitMu →
	// s.mu, see applyPolicyExport).
	regFence, registered := s.reg.Fence(subj)
	s.mu.Lock()
	// The latch freezes every policy file mutation; only a restart
	// reconciles (relay-write parity).
	if recovery := s.policyRecovery.Load(); recovery != nil {
		s.mu.Unlock()
		return http.StatusServiceUnavailable, fmt.Errorf("policy persistence recovery required: %s", recovery.reason)
	}
	// At-least-once delivery: never roll a newer local revision back. The
	// guard requires the stored fence to match the envelope — a newer file
	// under an old incarnation is stale local state the import must
	// supersede, not ack.
	if fs, fsErr := s.policyFiles.storeFor(subj); fsErr == nil {
		if cur, snapErr := fs.Snapshot(); snapErr == nil && cur.Exists() {
			if curPF, _, decErr := policy.DecodePolicyFile(cur.Data()); decErr == nil &&
				curPF.Incarnation == fence.RuntimeInstanceID && curPF.AttachmentID == fence.AttachmentID &&
				curPF.Revision > pf.Revision {
				s.mu.Unlock()
				log.Infof("subject %s: policy import superseded (local revision %d > bundle revision %d), idempotent ack", subj, curPF.Revision, pf.Revision)
				return http.StatusOK, nil
			}
		}
	}
	if registered && !regFence.Matches(fence) {
		s.mu.Unlock()
		return http.StatusConflict, fmt.Errorf("stale policy import (fence mismatch) for subject %s", subj)
	}
	sealed := false
	if e := s.policies[subj]; e != nil && e.sealed {
		sealed = true
	}
	s.mu.Unlock()

	err = s.persistPolicyCandidateLocked(
		subj,
		func(fs vaultFileStore) (policy.FileMutationState, error) {
			return fs.SaveRaw(payload)
		},
		func() error {
			if !registered {
				// Before SET_BINDING: registration reloads and validates.
				s.mu.Lock()
				delete(s.policies, subj)
				s.mu.Unlock()
				return s.policyFiles.unseal(subj)
			}
			return s.installImportedPolicyLocked(subj, fence, pf.Revision, pol, sealed)
		},
	)
	if err != nil {
		log.Errorf("subject %s: policy import failed: %v", subj, err)
		status := http.StatusInternalServerError
		if recovery := s.policyRecovery.Load(); recovery != nil {
			status = http.StatusServiceUnavailable
		}
		return status, errors.New("policy import persistence failure")
	}
	if registered {
		log.Infof("subject %s: policy imported from snapshot bundle (revision %d, re-stamped to %s/%s)",
			subj, pf.Revision, fence.RuntimeInstanceID, fence.AttachmentID)
	} else {
		log.Infof("subject %s: policy bundle landed for the next registration (revision %d, re-stamped to %s/%s)",
			subj, pf.Revision, fence.RuntimeInstanceID, fence.AttachmentID)
	}
	return http.StatusOK, nil
}

// installImportedPolicyLocked binds the imported revision into the live
// per-subject record under the restored fence, replacing any stale record,
// and unseals it. Ordering inside the commit protocol's apply step: the
// durable unseal FIRST (a failure here mutates nothing live — the commit
// protocol rolls the file back and the seal stays), then the state/fence
// re-read, then enforcement, then the record. Enforcement runs WITHOUT
// s.mu (it takes the registry write lock); the s.mu suffix is the
// docstring's "Locked" sense: map mutations under s.mu.
func (s *fastSandboxPolicyServer) installImportedPolicyLocked(subj subject.Subject, fence subject.Fencing, revision int64, pol *policy.NetworkPolicy, wasSealed bool) error {
	if wasSealed {
		if err := s.policyFiles.unseal(subj); err != nil {
			return err
		}
	}
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
	s.policies[subj] = &policyEntry{revision: revision, fence: fence}
	s.mu.Unlock()
	return nil
}

// readPolicyBundle reads the driver-staged bundle source with a hard size
// cap — a read-only lookup in the driver's trust domain, so plain bounded
// I/O suffices (writes keep the hardened atomic machinery).
func readPolicyBundle(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxPolicySnapshotBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxPolicySnapshotBytes {
		return nil, errPolicySnapshotTooLarge
	}
	return data, nil
}
