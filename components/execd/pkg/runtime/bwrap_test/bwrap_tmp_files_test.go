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

//go:build linux && bwrap

package bwrap_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alibaba/opensandbox/execd/pkg/isolation"
	"github.com/alibaba/opensandbox/execd/pkg/runtime"
)

// newStrictRunner creates a runner whose upper root lives in a known temp
// dir, so tests can locate the session /tmp backing directories on the host.
func newStrictRunner(t *testing.T) (*runtime.IsolatedRunner, string) {
	t.Helper()
	upperRoot := filepath.Join(t.TempDir(), "isolation")
	r := newRunnerWithConfig(t, isolation.Config{
		UpperRoot:       upperRoot,
		UpperMaxBytes:   1 << 30,
		AllowedWritable: []string{"/tmp"},
	})
	return r, upperRoot
}

// strictSession creates a default (strict profile) session: its /tmp is the
// session-private bind backed by a host dir under the runner's upper root.
func strictSession(t *testing.T, r *runtime.IsolatedRunner) string {
	t.Helper()
	id, err := r.CreateIsolatedSession(&runtime.IsolatedSessionOptions{
		WorkspacePath: t.TempDir(),
		WorkspaceMode: "rw",
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.DeleteIsolatedSession(id) })
	return id
}

// tmpBackingDir returns the /tmp backing directory of the single live
// session under upperRoot.
func tmpBackingDir(t *testing.T, upperRoot string) string {
	t.Helper()
	hits, err := filepath.Glob(filepath.Join(upperRoot, "*", "tmp"))
	require.NoError(t, err)
	require.Len(t, hits, 1, "expected exactly one session /tmp backing dir under %s", upperRoot)
	return hits[0]
}

// TestTmpFiles_RunWriteVisibleViaFilesAPI is the issue #2413 scenario: a
// command inside the strict session writes /tmp with shell redirection, and
// the session files API must read the same data back through /tmp.
func TestTmpFiles_RunWriteVisibleViaFilesAPI(t *testing.T) {
	r, upperRoot := newStrictRunner(t)
	id := strictSession(t, r)
	backing := tmpBackingDir(t, upperRoot)

	runInSession(t, r, id, "echo run-data > /tmp/run.txt", nil)

	// Host side: the write landed in the session's backing dir.
	host, err := os.ReadFile(filepath.Join(backing, "run.txt"))
	require.NoError(t, err)
	assert.Equal(t, "run-data\n", string(host))

	// Files API side: /tmp routes to the same directory.
	mv, err := r.GetMergedView(id)
	require.NoError(t, err)
	data, err := mv.ReadFile("/tmp/run.txt")
	require.NoError(t, err, "files API must read data run wrote into /tmp")
	assert.Equal(t, "run-data\n", string(data))
}

// TestTmpFiles_APIWriteVisibleToRun is the reverse direction: the files API
// writes /tmp, and a shell command inside the session observes it.
func TestTmpFiles_APIWriteVisibleToRun(t *testing.T) {
	r, upperRoot := newStrictRunner(t)
	id := strictSession(t, r)
	backing := tmpBackingDir(t, upperRoot)

	mv, err := r.GetMergedView(id)
	require.NoError(t, err)
	require.NoError(t, mv.WriteFile("/tmp/api.txt", []byte("api-data"), 0o644))

	host, err := os.ReadFile(filepath.Join(backing, "api.txt"))
	require.NoError(t, err)
	assert.Equal(t, "api-data", string(host))

	var lines []string
	runInSession(t, r, id, "cat /tmp/api.txt", func(line string) { lines = append(lines, line) })
	assert.Equal(t, []string{"api-data"}, lines)
}

// TestTmpFiles_SessionPrivateAndTeardown: two strict sessions see two
// distinct /tmp namespaces, and deleting a session removes its /tmp backing
// directory together with the rest of its session state.
func TestTmpFiles_SessionPrivateAndTeardown(t *testing.T) {
	r, upperRoot := newStrictRunner(t)
	idA := strictSession(t, r)
	idB := strictSession(t, r)

	runInSession(t, r, idA, "echo secret-a > /tmp/a.txt", nil)
	runInSession(t, r, idB, "echo secret-b > /tmp/b.txt", nil)

	mvA, err := r.GetMergedView(idA)
	require.NoError(t, err)
	mvB, err := r.GetMergedView(idB)
	require.NoError(t, err)

	data, err := mvA.ReadFile("/tmp/a.txt")
	require.NoError(t, err)
	assert.Equal(t, "secret-a\n", string(data))

	_, err = mvB.ReadFile("/tmp/a.txt")
	require.Error(t, err, "session B must not see session A's /tmp content")
	_, err = mvA.ReadFile("/tmp/b.txt")
	require.Error(t, err, "session A must not see session B's /tmp content")

	require.NoError(t, r.DeleteIsolatedSession(idA))
	_, err = mvA.ReadFile("/tmp/a.txt")
	require.Error(t, err, "deleted session's files view must be gone")

	// Session A's subtree (including its /tmp backing dir) is removed;
	// session B's backing dir and content survive.
	remainingDirs, err := filepath.Glob(filepath.Join(upperRoot, "*", "tmp"))
	require.NoError(t, err)
	require.Len(t, remainingDirs, 1, "only session B's /tmp backing dir should remain")
	remaining, err := filepath.Glob(filepath.Join(upperRoot, "*", "tmp", "a.txt"))
	require.NoError(t, err)
	assert.Empty(t, remaining, "session A's /tmp files must be gone after delete")

	data, err = mvB.ReadFile("/tmp/b.txt")
	require.NoError(t, err)
	assert.Equal(t, "secret-b\n", string(data))
}

// TestTmpFiles_MountOnTmpServedByFilesAPI: a session mount covering /tmp
// replaces the session-private bind inside the namespace, and the files API
// must follow the same priority — serving the covering mount's view, not a
// host bind. (An overlay-mode /tmp lower cannot stack in every environment,
// so the covering mount uses rw bind semantics.)
func TestTmpFiles_MountOnTmpServedByFilesAPI(t *testing.T) {
	r, _ := newStrictRunner(t)

	id, err := r.CreateIsolatedSession(&runtime.IsolatedSessionOptions{
		WorkspacePath: t.TempDir(),
		WorkspaceMode: "rw",
		Overlays: []runtime.IsolatedOverlayOptions{
			{Path: "/tmp", Mode: "rw"},
		},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = r.DeleteIsolatedSession(id) })

	runInSession(t, r, id, "echo mount-tmp > /tmp/mounted.txt", nil)

	mv, err := r.GetMergedView(id)
	require.NoError(t, err)
	data, err := mv.ReadFile("/tmp/mounted.txt")
	require.NoError(t, err, "files API must serve a mount covering /tmp")
	assert.Equal(t, "mount-tmp\n", string(data))
}
