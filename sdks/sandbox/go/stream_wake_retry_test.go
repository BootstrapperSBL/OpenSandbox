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

package opensandbox

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func writeStreamWakeTimeout(w http.ResponseWriter) {
	w.Header().Set(wakeMarkerHeader, wakeMarkerExpired)
	w.Header().Set("Retry-After", "0")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte(`{"code":"sandbox_wake_timeout","message":"restore in progress"}`))
}

// A bare 503 carries no proof that the request was not forwarded, so the stream
// bootstrap must stay unwrapped by any retry (OSEP-0017). This pins the boundary
// the OSEP-0024 wake retry must not cross.
func TestStreamWakeRetry_Bare503OnCommandStreamIsNotRetried(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"code":"UNAVAILABLE","message":"try again"}`))
	}))
	defer srv.Close()

	client := NewExecdClient(srv.URL, "tok", WithRetry(RetryConfig{
		MaxRetries:          2,
		WakeMaxAttempts:     5,
		WakeOverallDeadline: time.Minute,
	}))

	err := client.RunCommand(context.Background(), RunCommandRequest{Command: "echo hello"}, func(StreamEvent) error {
		return nil
	})
	require.Error(t, err, "a bare 503 on a POST stream must not be replayed")
	require.Equal(t, 1, int(attempts.Load()), "stream bootstrap attempts")
	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	require.Equal(t, http.StatusServiceUnavailable, apiErr.StatusCode, "status code")
}

// Exhausting the wake budget on a stream must surface the same typed error as
// the non-streaming paths so callers can tell "never forwarded" from a command
// failure.
func TestStreamWakeRetry_BudgetExhaustionReturnsTypedError(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		writeStreamWakeTimeout(w)
	}))
	defer srv.Close()

	client := NewExecdClient(srv.URL, "tok", WithRetry(wakeConfig(3, time.Minute)))

	err := client.RunCommand(context.Background(), RunCommandRequest{Command: "echo hello"}, func(StreamEvent) error {
		return nil
	})
	require.Error(t, err, "exhausted wake retry on a stream")
	var wakeErr *SandboxWakeTimeoutError
	require.ErrorAs(t, err, &wakeErr)
	require.Equal(t, 3, wakeErr.Attempts, "wake attempts")
	require.Equal(t, 3, int(attempts.Load()), "stream bootstrap attempts")
}
