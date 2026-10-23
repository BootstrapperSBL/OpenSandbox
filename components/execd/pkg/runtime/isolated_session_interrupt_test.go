// Copyright 2026 The OpenSandbox Authors

//go:build !windows

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

package runtime

import (
	"context"
	"errors"
	"testing"
	"time"
)

func newInterruptTestSession(t *testing.T) (*IsolatedRunner, string) {
	t.Helper()
	runner := newTestRunner(t)
	id, err := runner.CreateIsolatedSession(&IsolatedSessionOptions{
		WorkspacePath: t.TempDir(),
		WorkspaceMode: "rw",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runner.DeleteIsolatedSession(id) })
	return runner, id
}

// TestRunInIsolatedSession_InterruptKeepsSessionAlive verifies the public
// contract that a cancelled run (client disconnect or timeout_seconds expiry)
// interrupts the running command without killing or deregistering the
// persistent session, so the next run on the same session succeeds.
func TestRunInIsolatedSession_InterruptKeepsSessionAlive(t *testing.T) {
	runner, id := newInterruptTestSession(t)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	err := runner.RunInIsolatedSession(ctx, id, "sleep 30", nil, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("interrupted run error = %v, want context.DeadlineExceeded", err)
	}

	s := runner.lookup(id)
	if s == nil {
		t.Fatal("session was removed after run cancellation")
	}
	if s.dead() {
		t.Fatal("session is dead after run cancellation")
	}

	// The same session must accept a follow-up run.
	var lines []string
	runCtx, runCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer runCancel()
	err = runner.RunInIsolatedSession(runCtx, id, "echo next", nil, func(line string) {
		lines = append(lines, line)
	})
	if err != nil {
		t.Fatalf("follow-up run: %v", err)
	}
	if len(lines) != 1 || lines[0] != "next" {
		t.Fatalf("follow-up output = %v, want [next]", lines)
	}
}

// TestRunInIsolatedSession_InterruptedRunDoesNotLeakIntoNext verifies that an
// interrupt ends the whole run when the code is wrapped in a subshell (envs
// supplied): later lines of the interrupted code must never execute and must
// not pollute the next run's output.
func TestRunInIsolatedSession_InterruptedRunDoesNotLeakIntoNext(t *testing.T) {
	runner, id := newInterruptTestSession(t)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	err := runner.RunInIsolatedSession(
		ctx,
		id,
		"sleep 30\necho SHOULD_NOT_APPEAR",
		map[string]string{"RUN_ENVELOPE": "1"},
		nil,
	)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("interrupted run error = %v, want context.DeadlineExceeded", err)
	}

	var lines []string
	runCtx, runCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer runCancel()
	err = runner.RunInIsolatedSession(runCtx, id, "echo next", nil, func(line string) {
		lines = append(lines, line)
	})
	if err != nil {
		t.Fatalf("follow-up run: %v", err)
	}
	if len(lines) != 1 || lines[0] != "next" {
		t.Fatalf("follow-up output = %v, want exactly [next]", lines)
	}
}

// TestRunInIsolatedSession_EscalatesWhenInterruptIgnored verifies that a
// command which ignores SIGINT cannot wedge the session's run mutex forever:
// the watcher escalates to SIGKILL, the run fails, and the wedged session is
// torn down so the failure is observable instead of a silent hang.
func TestRunInIsolatedSession_EscalatesWhenInterruptIgnored(t *testing.T) {
	runner, id := newInterruptTestSession(t)

	originalEscalation := isolatedInterruptEscalationTimeout
	isolatedInterruptEscalationTimeout = 300 * time.Millisecond
	t.Cleanup(func() { isolatedInterruptEscalationTimeout = originalEscalation })

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := runner.RunInIsolatedSession(ctx, id, "trap '' INT; sleep 30", nil, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("escalated run error = %v, want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("escalated run took %v; SIGINT-immune command was not killed", elapsed)
	}

	// The SIGKILL reaps the session process, so the session must turn dead
	// and reject further work. (The test isolator's lifecycle only drains on
	// explicit delete, so registry removal is not asserted here.)
	deadline := time.Now().Add(5 * time.Second)
	for {
		s := runner.lookup(id)
		if s == nil {
			t.Fatal("session record should still exist until deletion")
		}
		if s.dead() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("session should be dead after SIGKILL escalation")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := runner.RunInIsolatedSession(context.Background(), id, "echo hi", nil, nil); !errors.Is(err, ErrSessionNotActive) {
		t.Fatalf("run on escalated session error = %v, want ErrSessionNotActive", err)
	}
}
