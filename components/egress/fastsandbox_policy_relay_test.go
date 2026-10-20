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

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alibaba/opensandbox/egress/pkg/constants"
	"github.com/alibaba/opensandbox/egress/pkg/subject"
)

// ---------------------------------------------------------------------------
// Relay policy surface: /policy/{sandboxUid}
// ---------------------------------------------------------------------------

const policyTestUID = "policy-u"

// policyAllow is a minimal effective policy.
func policyAllow() string {
	return `{"defaultAction":"deny","egress":[{"action":"allow","target":"api.example.com"}]}`
}

func policyAllowAlt() string {
	return `{"defaultAction":"deny","egress":[{"action":"allow","target":"other.example.com"}]}`
}

// policyPutDoc wraps a policy body in the relay document with an optional
// precondition (either spelling).
func policyPutDoc(policyBody string, revision int64, withRevision, withExpected bool) string {
	var b strings.Builder
	b.WriteString(`{"policy":`)
	b.WriteString(policyBody)
	if withRevision {
		b.WriteString(`,"revision":`)
		b.WriteString(strconv.FormatInt(revision, 10))
	}
	if withExpected {
		b.WriteString(`,"expectedRevision":`)
		b.WriteString(strconv.FormatInt(revision, 10))
	}
	b.WriteString(`}`)
	return b.String()
}

// doPolicy drives one relay request against the surface; incarnation is the
// optional expectedIncarnation precondition header.
func doPolicy(t *testing.T, srv *fastSandboxPolicyServer, method, uid, body, incarnation string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, constants.PolicyRelayPathPrefix+uid, strings.NewReader(body))
	if incarnation != "" {
		req.Header.Set(constants.EgressVaultIncarnationHeader, incarnation)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

// mustPolicyRevision decodes a relay GET/PUT body's revision.
func mustPolicyRevision(t *testing.T, rec *httptest.ResponseRecorder) (int64, policyRelayDocument) {
	t.Helper()
	require.Contains(t, []int{http.StatusOK, http.StatusCreated}, rec.Code, rec.Body.String())
	var doc policyRelayDocument
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &doc))
	return doc.Revision, doc
}

func TestPolicyRelayUnknownSubject404NoCache(t *testing.T) {
	srv, _, _ := fastSandboxTestServer(t)
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		rec := doPolicy(t, srv, method, "ghost", policyPutDoc(policyAllow(), 0, false, false), "")
		assert.Equal(t, http.StatusNotFound, rec.Code, method)
	}
	// No policy record was materialized for the unknown subject.
	srv.mu.Lock()
	_, stored := srv.policies[subject.FromSandboxUID("ghost")]
	srv.mu.Unlock()
	assert.False(t, stored, "the relay surface never materializes state for an unregistered subject")
}

func TestPolicyRelayPutReplacesSeededRecord(t *testing.T) {
	srv, reg, _ := fastSandboxTestServer(t)
	setBindingAndReady(t, srv, reg, policyTestUID, vaultTestIP, strPtr(policyAllow()))

	// The binding input seeded the record at revision 1: GET serves the
	// seeded policy even before any relay write.
	rec := doPolicy(t, srv, http.MethodGet, policyTestUID, "", "")
	rev, doc := mustPolicyRevision(t, rec)
	require.Equal(t, int64(1), rev)
	assert.Contains(t, string(doc.Policy), "api.example.com")

	// PUT replaces at the successor revision.
	rec = doPolicy(t, srv, http.MethodPut, policyTestUID, policyPutDoc(policyAllowAlt(), 0, false, false), "")
	require.Equal(t, http.StatusOK, rec.Code)
	rev, doc = mustPolicyRevision(t, rec)
	assert.Equal(t, int64(2), rev)
	assert.Contains(t, string(doc.Policy), "other.example.com")

	// Enforcement followed the relay write.
	s := subject.FromSandboxUID(policyTestUID)
	assert.Equal(t, subject.StateActive, mustState(reg.Get(s)))
	assert.Equal(t, "allow", reg.UserPolicy(s).Evaluate("other.example.com"))

	// GET echoes the recorded policy + revision.
	rec = doPolicy(t, srv, http.MethodGet, policyTestUID, "", "")
	rev, doc = mustPolicyRevision(t, rec)
	assert.Equal(t, int64(2), rev)
	assert.Contains(t, string(doc.Policy), "other.example.com")
}

func TestPolicyRelayPreconditions(t *testing.T) {
	srv, reg, _ := fastSandboxTestServer(t)
	setBindingAndReady(t, srv, reg, policyTestUID, vaultTestIP, strPtr(policyAllow()))

	// The binding input seeded revision 1; the first relay PUT is a replace.
	rec := doPolicy(t, srv, http.MethodPut, policyTestUID, policyPutDoc(policyAllowAlt(), 1, false, true), "")
	require.Equal(t, http.StatusOK, rec.Code)

	// Stale expectedRevision is a 412.
	rec = doPolicy(t, srv, http.MethodPut, policyTestUID, policyPutDoc(policyAllow(), 1, false, true), "")
	require.Equal(t, http.StatusPreconditionFailed, rec.Code)

	// The GET revision acts as the precondition (round trip).
	rec = doPolicy(t, srv, http.MethodGet, policyTestUID, "", "")
	rev, _ := mustPolicyRevision(t, rec)
	require.Equal(t, int64(2), rev)
	rec = doPolicy(t, srv, http.MethodPut, policyTestUID, policyPutDoc(policyAllowAlt(), rev, true, false), "")
	require.Equal(t, http.StatusOK, rec.Code)
	rev, _ = mustPolicyRevision(t, rec)
	require.Equal(t, int64(3), rev)

	// Stale round-trip revision: 412.
	rec = doPolicy(t, srv, http.MethodPut, policyTestUID, policyPutDoc(policyAllowAlt(), rev-1, true, false), "")
	require.Equal(t, http.StatusPreconditionFailed, rec.Code)

	// Both spellings agreeing is accepted.
	rec = doPolicy(t, srv, http.MethodPut, policyTestUID, policyPutDoc(policyAllow(), rev, true, true), "")
	require.Equal(t, http.StatusOK, rec.Code)

	// Both spellings disagreeing is a 400.
	rec = doPolicy(t, srv, http.MethodPut, policyTestUID, `{"policy":`+policyAllow()+`,"revision":1,"expectedRevision":2}`, "")
	require.Equal(t, http.StatusBadRequest, rec.Code)

	// DELETE lands a deny tombstone at the successor revision; a conditional
	// PUT against the pre-delete revision is a 412.
	rec = doPolicy(t, srv, http.MethodDelete, policyTestUID, "", "")
	require.Equal(t, http.StatusNoContent, rec.Code)
	rec = doPolicy(t, srv, http.MethodPut, policyTestUID, policyPutDoc(policyAllow(), 4, false, true), "")
	require.Equal(t, http.StatusPreconditionFailed, rec.Code)

	// Unconditional PUT replaces the tombstone at the successor revision.
	rec = doPolicy(t, srv, http.MethodPut, policyTestUID, policyPutDoc(policyAllow(), 0, false, false), "")
	require.Equal(t, http.StatusOK, rec.Code)
	rev, doc := mustPolicyRevision(t, rec)
	assert.Equal(t, int64(6), rev)
	assert.Contains(t, string(doc.Policy), "api.example.com")
}

func TestPolicyRelayInvalidPolicyKeepsLastGood(t *testing.T) {
	srv, reg, _ := fastSandboxTestServer(t)
	setBindingAndReady(t, srv, reg, policyTestUID, vaultTestIP, strPtr(policyAllow()))

	rec := doPolicy(t, srv, http.MethodPut, policyTestUID, policyPutDoc(policyAllowAlt(), 0, false, false), "")
	require.Equal(t, http.StatusOK, rec.Code)

	// Invalid policy content is a 400 NACK; last-good kept. (defaultAction
	// is not action-validated by the parser; egress rule actions are.)
	rec = doPolicy(t, srv, http.MethodPut, policyTestUID, policyPutDoc(`{"defaultAction":"deny","egress":[{"action":"bogus","target":"x.com"}]}`, 0, false, false), "")
	require.Equal(t, http.StatusBadRequest, rec.Code)
	rec = doPolicy(t, srv, http.MethodPut, policyTestUID, `{`, "")
	require.Equal(t, http.StatusBadRequest, rec.Code)
	rec = doPolicy(t, srv, http.MethodPut, policyTestUID, `{"unknownField":1}`, "")
	require.Equal(t, http.StatusBadRequest, rec.Code)
	rec = doPolicy(t, srv, http.MethodPut, policyTestUID, `{}`, "")
	require.Equal(t, http.StatusBadRequest, rec.Code)

	s := subject.FromSandboxUID(policyTestUID)
	assert.Equal(t, "allow", reg.UserPolicy(s).Evaluate("other.example.com"), "last-good policy untouched")
}

func TestPolicyRelayDeleteEnforcesDenyTombstone(t *testing.T) {
	srv, reg, nft := fastSandboxTestServer(t)
	s := setBindingAndReady(t, srv, reg, policyTestUID, vaultTestIP, strPtr(policyAllow()))
	require.Equal(t, subject.StateActive, mustState(reg.Get(s)))

	// DELETE removes the seeded policy (revision 1 → tombstone at 2) and
	// enforces default-deny IN PLACE: the subject stays active (a later
	// relay PUT re-enables immediately — the generic relay never replays a
	// data-plane-ready hook).
	rec := doPolicy(t, srv, http.MethodDelete, policyTestUID, "", "")
	require.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, subject.StateActive, mustState(reg.Get(s)))
	assert.Equal(t, "deny", reg_UserEvaluate(srv, s, "api.example.com"))
	nft.mu.Lock()
	require.NotNil(t, nft.lastPolicy)
	assert.Equal(t, "deny", nft.lastPolicy.Evaluate("api.example.com"), "the deny tombstone is enforced")
	nft.mu.Unlock()

	// The tombstone is authoritative: GET serves the default-deny record at
	// the successor revision, and a binding replay cannot resurrect the
	// deleted policy.
	rec = doPolicy(t, srv, http.MethodGet, policyTestUID, "", "")
	rev, doc := mustPolicyRevision(t, rec)
	assert.Equal(t, int64(2), rev)
	assert.Contains(t, string(doc.Policy), `"defaultAction":"deny"`)
	assert.NotContains(t, string(doc.Policy), "api.example.com")
	rec = doAction(t, srv, bindBody(t, policyTestUID, vaultTestIP, testFenceR, testFenceA, 2, strPtr(policyAllow())))
	require.Equal(t, http.StatusOK, rec.Code)
	rec = doPolicy(t, srv, http.MethodGet, policyTestUID, "", "")
	rev, doc = mustPolicyRevision(t, rec)
	assert.Equal(t, int64(2), rev, "the tombstone survives the binding replay")
	assert.NotContains(t, string(doc.Policy), "api.example.com")

	// DELETE is idempotent (the tombstone replaces itself at the successor
	// revision).
	rec = doPolicy(t, srv, http.MethodDelete, policyTestUID, "", "")
	assert.Equal(t, http.StatusNoContent, rec.Code)
	rev, _ = mustPolicyRevision(t, doPolicy(t, srv, http.MethodGet, policyTestUID, "", ""))
	assert.Equal(t, int64(3), rev)

	// Re-add goes through the relay: the PUT replaces the tombstone and
	// re-enables immediately on the still-active subject.
	rec = doPolicy(t, srv, http.MethodPut, policyTestUID, policyPutDoc(policyAllow(), 3, false, true), "")
	require.Equal(t, http.StatusOK, rec.Code)
	rev, doc = mustPolicyRevision(t, rec)
	assert.Equal(t, int64(4), rev)
	assert.Equal(t, subject.StateActive, mustState(reg.Get(s)))
	assert.Equal(t, "allow", reg_UserEvaluate(srv, s, "api.example.com"))
}

func TestPolicyRelayDenyingSubjectHoldsPending(t *testing.T) {
	srv, _, _ := fastSandboxTestServer(t)

	// SET_BINDING only: subject registered, still denying.
	rec := doAction(t, srv, bindBody(t, policyTestUID, vaultTestIP, testFenceR, testFenceA, 1, strPtr(policyAllow())))
	require.Equal(t, http.StatusOK, rec.Code)

	// A relay PUT while denying replaces the pending policy (held to the
	// data-plane-ready barrier) at the successor revision.
	rec = doPolicy(t, srv, http.MethodPut, policyTestUID, policyPutDoc(policyAllowAlt(), 1, false, true), "")
	require.Equal(t, http.StatusOK, rec.Code)
	rev, doc := mustPolicyRevision(t, rec)
	assert.Equal(t, int64(2), rev)
	assert.Contains(t, string(doc.Policy), "other.example.com")

	// GET serves the pending policy while held.
	rec = doPolicy(t, srv, http.MethodGet, policyTestUID, "", "")
	_, doc = mustPolicyRevision(t, rec)
	assert.Contains(t, string(doc.Policy), "other.example.com")

	// data-plane-ready activates the relayed policy.
	rec = doAction(t, srv, hookBody(t, policyTestUID, testFenceR, testFenceA, constants.HookRuntimeReady))
	require.Equal(t, http.StatusOK, rec.Code)
	rec = doAction(t, srv, hookBody(t, policyTestUID, testFenceR, testFenceA, constants.HookDataPlaneReady))
	require.Equal(t, http.StatusOK, rec.Code)
	s := subject.FromSandboxUID(policyTestUID)
	assert.Equal(t, "allow", reg_UserEvaluate(srv, s, "other.example.com"))
}

// reg_UserEvaluate evaluates the subject's recorded user policy (test aid to
// keep assertions readable).
func reg_UserEvaluate(srv *fastSandboxPolicyServer, s subject.Subject, domain string) string {
	pol := srv.reg.UserPolicy(s)
	if pol == nil {
		return "no-policy"
	}
	return pol.Evaluate(domain)
}

func TestPolicyRelayIncarnationPrecondition(t *testing.T) {
	srv, reg, _ := fastSandboxTestServer(t)
	setBindingAndReady(t, srv, reg, policyTestUID, vaultTestIP, strPtr(policyAllow()))

	rec := doPolicy(t, srv, http.MethodPut, policyTestUID, policyPutDoc(policyAllowAlt(), 1, false, true), testFenceR)
	require.Equal(t, http.StatusOK, rec.Code)

	rec = doPolicy(t, srv, http.MethodPut, policyTestUID, policyPutDoc(policyAllow(), 1, false, true), "runtime-999")
	require.Equal(t, http.StatusPreconditionFailed, rec.Code)

	rec = doPolicy(t, srv, http.MethodGet, policyTestUID, "", "runtime-999")
	require.Equal(t, http.StatusPreconditionFailed, rec.Code)
	rec = doPolicy(t, srv, http.MethodGet, policyTestUID, "", testFenceR)
	require.Equal(t, http.StatusOK, rec.Code)

	rec = doPolicy(t, srv, http.MethodDelete, policyTestUID, "", "runtime-999")
	require.Equal(t, http.StatusPreconditionFailed, rec.Code)
}

func TestPolicyRelayMethodNotAllowed(t *testing.T) {
	srv, reg, _ := fastSandboxTestServer(t)
	setBindingAndReady(t, srv, reg, policyTestUID, vaultTestIP, strPtr(policyAllow()))

	rec := doPolicy(t, srv, http.MethodPost, policyTestUID, policyPutDoc(policyAllow(), 0, false, false), "")
	require.Equal(t, http.StatusMethodNotAllowed, rec.Code)
	assert.Contains(t, rec.Header().Get("Allow"), "PUT")

	rec = doPolicy(t, srv, http.MethodPatch, policyTestUID, "{}", "")
	require.Equal(t, http.StatusMethodNotAllowed, rec.Code)

	// The bare /policy path redirects into the subtree; the old UID-header
	// surface stays gone.
	rec = doRequest(t, srv, http.MethodGet, "/policy", "")
	assert.NotEqual(t, http.StatusOK, rec.Code)
}

func TestPolicyRelayRebindResetsRecord(t *testing.T) {
	srv, reg, _ := fastSandboxTestServer(t)
	s := setBindingAndReady(t, srv, reg, policyTestUID, vaultTestIP, strPtr(policyAllow()))

	rec := doPolicy(t, srv, http.MethodPut, policyTestUID, policyPutDoc(policyAllowAlt(), 0, false, false), "")
	require.Equal(t, http.StatusOK, rec.Code)

	// Rebind: same UID, NEW runtime instance — the recorded policy is gone.
	const newRuntime = "runtime-2"
	rec = doAction(t, srv, bindBody(t, policyTestUID, vaultTestIP, newRuntime, "attachment-2", 2, strPtr(policyAllow())))
	require.Equal(t, http.StatusOK, rec.Code)
	rec = doAction(t, srv, hookBody(t, policyTestUID, newRuntime, "attachment-2", constants.HookDataPlaneReady))
	require.Equal(t, http.StatusOK, rec.Code)

	// The relayed (previous instance's) policy is gone: GET serves the NEW
	// binding input at revision 1 — the successor was reseeded.
	rec = doPolicy(t, srv, http.MethodGet, policyTestUID, "", "")
	rev, doc := mustPolicyRevision(t, rec)
	assert.Equal(t, int64(1), rev)
	assert.Contains(t, string(doc.Policy), "api.example.com")
	assert.NotContains(t, string(doc.Policy), "other.example.com", "the rebind discards the previous instance's recorded policy")
	assert.Equal(t, "allow", reg_UserEvaluate(srv, s, "api.example.com"), "the new binding input seeds the successor")

	// The old incarnation cannot write into the successor.
	rec = doPolicy(t, srv, http.MethodPut, policyTestUID, policyPutDoc(policyAllow(), 1, false, true), testFenceR)
	require.Equal(t, http.StatusPreconditionFailed, rec.Code)
}
