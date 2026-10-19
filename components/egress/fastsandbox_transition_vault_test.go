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
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alibaba/opensandbox/egress/pkg/constants"
	"github.com/alibaba/opensandbox/egress/pkg/credentialvault"
	"github.com/alibaba/opensandbox/egress/pkg/policy"
	"github.com/alibaba/opensandbox/egress/pkg/subject"
	"github.com/stretchr/testify/require"
)

type transitionSlowWriter struct {
	header  http.Header
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *transitionSlowWriter) block()                      { w.once.Do(func() { close(w.entered); <-w.release }) }
func (w *transitionSlowWriter) Header() http.Header         { w.block(); return w.header }
func (w *transitionSlowWriter) WriteHeader(int)             { w.block() }
func (w *transitionSlowWriter) Write(p []byte) (int, error) { w.block(); return len(p), nil }

func assertTransitionResponseUnlocked(t *testing.T, srv *fastSandboxPolicyServer, handler http.HandlerFunc, req *http.Request) {
	t.Helper()
	w := &transitionSlowWriter{header: make(http.Header), entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	go func() { defer close(done); handler(w, req) }()
	select {
	case <-w.entered:
	case <-time.After(time.Second):
		t.Fatal("response not reached")
	}
	free := srv.mu.TryLock()
	if free {
		srv.mu.Unlock()
	}
	close(w.release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler did not finish")
	}
	require.True(t, free, "HTTP response must not hold subject state lock")
}

func TestTransitionRelayResponseOutsideLock(t *testing.T) {
	for _, mode := range []string{"unknown", "create", "replace-error", "persistent-create", "persistent-delete", "get"} {
		t.Run(mode, func(t *testing.T) {
			srv, reg, _ := fastSandboxTestServer(t)
			if strings.HasPrefix(mode, "persistent") {
				h := newVaultPersistHarness(t)
				srv, reg = h.srv, h.reg
			}
			if mode != "unknown" {
				vaultReadySubject(t, srv, reg)
			}
			method, body := http.MethodPost, vaultCredential()
			if mode == "replace-error" || mode == "persistent-delete" || mode == "get" {
				require.Equal(t, http.StatusCreated, doVault(t, srv, http.MethodPost, vaultTestUID, vaultCredential(), "").Code)
			}
			switch mode {
			case "replace-error":
				method, body = http.MethodPut, vaultPut("999")
			case "persistent-delete":
				method, body = http.MethodDelete, ""
			case "get":
				method, body = http.MethodGet, ""
			}
			req := httptest.NewRequest(method, constants.VaultRelayPathPrefix+vaultTestUID, strings.NewReader(body))
			assertTransitionResponseUnlocked(t, srv, srv.handleVaultRelay, req)
		})
	}
}

func TestTransitionActiveResponseOutsideLock(t *testing.T) {
	for _, mode := range []string{"ok", "not-modified", "missing", "bad-tag"} {
		t.Run(mode, func(t *testing.T) {
			srv, reg, _ := fastSandboxTestServer(t)
			if mode != "missing" {
				vaultReadySubject(t, srv, reg)
				require.Equal(t, http.StatusCreated, doVault(t, srv, http.MethodPost, vaultTestUID, vaultCredential(), "").Code)
			}
			req := httptest.NewRequest(http.MethodGet, "/credential-vault/_active?clientIp="+vaultTestIP, nil)
			if mode == "not-modified" {
				rec := httptest.NewRecorder()
				srv.handleCredentialVaultActive(rec, req)
				require.Equal(t, http.StatusOK, rec.Code)
				req.Header.Set("If-None-Match", rec.Header().Get("ETag"))
			}
			if mode == "bad-tag" {
				req.Header.Set("If-None-Match", "invalid")
			}
			assertTransitionResponseUnlocked(t, srv, srv.handleCredentialVaultActive, req)
		})
	}
}

func TestTransitionZeroFenceDoesNotCreateStore(t *testing.T) {
	srv, _, _ := fastSandboxTestServer(t)
	require.Nil(t, srv.vaultFor(subject.FromSandboxUID("absent")))
	require.Empty(t, srv.vaults)
}

func TestTransitionSnapshotGuardsAndPreSetImport(t *testing.T) {
	t.Run("export-initial", func(t *testing.T) {
		h := newVaultPersistHarness(t)
		subj := h.snapshotSubject(t)
		fence, _ := h.reg.Fence(subj)
		h.srv.mu.Lock()
		h.srv.rebinds[subj] = &subjectRebind{expectedNew: fence}
		h.srv.mu.Unlock()
		path := filepath.Join(t.TempDir(), "bundle.json")
		rec := doAction(t, h.srv, snapshotBody(t, snapshotTestUID, testFenceR, testFenceA, "VAULT_EXPORT", path))
		require.Equal(t, http.StatusServiceUnavailable, rec.Code)
		require.False(t, h.fakeForPath(path).exists)
		require.False(t, h.srv.vaults[subj].sealed)
	})
	t.Run("export-final", func(t *testing.T) {
		h := newVaultPersistHarness(t)
		subj := h.snapshotSubject(t)
		fence, _ := h.reg.Fence(subj)
		path := filepath.Join(t.TempDir(), "bundle.json")
		h.fakeForPath(path).onSave = func() { h.srv.mu.Lock(); h.srv.rebinds[subj] = &subjectRebind{expectedNew: fence}; h.srv.mu.Unlock() }
		rec := doAction(t, h.srv, snapshotBody(t, snapshotTestUID, testFenceR, testFenceA, "VAULT_EXPORT", path))
		require.Equal(t, http.StatusServiceUnavailable, rec.Code)
		require.True(t, h.fakeForPath(path).exists, "copy may complete but must not seal")
		require.False(t, h.srv.vaults[subj].sealed)
	})
	t.Run("import-before-newer-revision-ack", func(t *testing.T) {
		h := newVaultPersistHarness(t)
		subj := h.snapshotSubject(t)
		path := filepath.Join(t.TempDir(), "bundle.json")
		h.seedBundle(t, path)
		h.seedVaultFile(snapshotTestUID, testFenceR, testFenceA, 10, vaultFullBody())
		before := append([]byte(nil), h.fileFor(snapshotTestUID).data...)
		calls := h.fileFor(snapshotTestUID).saveCalls
		fence, _ := h.reg.Fence(subj)
		h.srv.mu.Lock()
		h.srv.rebinds[subj] = &subjectRebind{expectedNew: fence}
		h.srv.mu.Unlock()
		body := snapshotBody(t, snapshotTestUID, testFenceR, testFenceA, "VAULT_IMPORT", path)
		require.Equal(t, http.StatusServiceUnavailable, doAction(t, h.srv, body).Code)
		require.Equal(t, before, h.fileFor(snapshotTestUID).data)
		require.Equal(t, calls, h.fileFor(snapshotTestUID).saveCalls)
		h.srv.mu.Lock()
		delete(h.srv.rebinds, subj)
		h.srv.mu.Unlock()
		require.Equal(t, http.StatusOK, doAction(t, h.srv, body).Code)
		require.Equal(t, before, h.fileFor(snapshotTestUID).data)
	})
	t.Run("import-after-terminal-purge", func(t *testing.T) {
		h := newVaultPersistHarness(t)
		subj := h.snapshotSubject(t)
		require.Equal(t, http.StatusOK, doAction(t, h.srv, removeBody(t, snapshotTestUID, testFenceR, testFenceA)).Code)
		_, registered := h.reg.Fence(subj)
		require.False(t, registered)
		require.False(t, h.fileFor(snapshotTestUID).exists)
		path := filepath.Join(t.TempDir(), "bundle.json")
		h.seedBundle(t, path)
		require.Equal(t, http.StatusOK, doAction(t, h.srv, snapshotBody(t, snapshotTestUID, snapshotResumeR, snapshotResumeA, "VAULT_IMPORT", path)).Code)
		vf, _, err := credentialvault.DecodeVaultFile(h.fileFor(snapshotTestUID).data)
		require.NoError(t, err)
		require.Equal(t, snapshotResumeR, vf.Incarnation)
		require.Equal(t, snapshotResumeA, vf.AttachmentID)
		require.Empty(t, h.srv.vaults, "pre-SET import remains file-only")
	})
}

func TestTransitionSharedActiveSnapshotContract(t *testing.T) {
	srv, reg, _ := fastSandboxTestServer(t)
	subj := vaultReadySubject(t, srv, reg)
	store := srv.vaultFor(subj)
	request := func(tag string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/credential-vault/_active", nil)
		req.Header.Set("If-None-Match", tag)
		rec := httptest.NewRecorder()
		handleActiveVaultSnapshot(rec, req, store)
		return rec
	}
	require.Equal(t, http.StatusNotFound, request("").Code)
	require.Equal(t, http.StatusCreated, doVault(t, srv, http.MethodPost, vaultTestUID, vaultCredential(), "").Code)
	rec := request("")
	require.Equal(t, http.StatusOK, rec.Code)
	require.NotEmpty(t, rec.Header().Get("ETag"))
	unchanged := request(rec.Header().Get("ETag"))
	require.Equal(t, http.StatusNotModified, unchanged.Code)
	require.Empty(t, unchanged.Body.String())
	require.Equal(t, http.StatusBadRequest, request("not-quoted").Code)
}

type transitionDeleteProbe struct {
	vaultFileStore
	remove func() (policy.FileMutationState, error)
}

func (f *transitionDeleteProbe) Delete() (policy.FileMutationState, error) { return f.remove() }

func TestTransitionTerminalPurgeRetryStaysAfterUnregisterUnderLock(t *testing.T) {
	h := newVaultPersistHarness(t)
	subj := h.snapshotSubject(t)
	file := h.fileFor(snapshotTestUID)
	calls := 0
	fail := true
	probe := &transitionDeleteProbe{vaultFileStore: file}
	probe.remove = func() (policy.FileMutationState, error) {
		calls++
		unlocked := h.srv.mu.TryLock()
		if unlocked {
			h.srv.mu.Unlock()
		}
		require.False(t, unlocked, "all terminal cleanup attempts share the subject lock")
		_, registered := h.reg.Fence(subj)
		require.False(t, registered, "terminal cleanup follows identity removal")
		if fail {
			return policy.FileUnknown, errors.New("persistent unlink failure")
		}
		return file.Delete()
	}
	h.vp.mu.Lock()
	h.vp.files[subj] = probe
	h.vp.mu.Unlock()
	require.Equal(t, http.StatusOK, doAction(t, h.srv, removeBody(t, snapshotTestUID, testFenceR, testFenceA)).Code)
	require.Equal(t, 2, calls, "terminal cleanup is a bounded retry, not a loop")
	require.True(t, file.exists)
	require.Empty(t, h.srv.vaults)
	vf, _, err := credentialvault.DecodeVaultFile(file.data)
	require.NoError(t, err)
	require.Equal(t, testFenceR, vf.Incarnation)
	require.Equal(t, testFenceA, vf.AttachmentID)
	fail = false
	require.Equal(t, http.StatusOK, doAction(t, h.srv, removeBody(t, snapshotTestUID, testFenceR, testFenceA)).Code)
	require.False(t, file.exists)
}
