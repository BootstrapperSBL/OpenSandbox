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

import assert from "node:assert/strict";
import test from "node:test";
import { Sandbox, SandboxManager, ConnectionConfig, SandboxApiException } from "../dist/index.js";

const context = { sandboxId: "sbx-1", backendType: "kubernetes", backendIdentifiers: { namespace: "tenant-ns" } };

function mockConfig(handler) {
  const config = new ConnectionConfig({
    domain: "localhost:8080", protocol: "http", apiKey: "key", headers: { "x-custom": "custom" },
  });
  Object.defineProperty(config, "fetch", { value: handler });
  config.withTransportIfMissing = () => config;
  return config;
}

test("manager diagnostics uses lifecycle transport and preserves descriptor metadata", async () => {
  const calls = [];
  const manager = SandboxManager.create({ connectionConfig: mockConfig(
    async (input) => {
      const req = input instanceof Request ? input : new Request(input);
      calls.push(req);
      assert.equal(req.headers.get("OPEN-SANDBOX-API-KEY"), "key");
      assert.equal(req.headers.get("x-custom"), "custom");
      const url = new URL(req.url);
      if (url.pathname.endsWith("/context")) return Response.json(context);
      assert.equal(url.searchParams.get("scope"), "all");
      const kind = url.pathname.endsWith("/logs") ? "logs" : "events";
      return Response.json({
        sandboxId: "sbx-1", kind, scope: "all", delivery: "url", contentType: "text/plain",
        contentUrl: "https://example.invalid/content", expiresAt: "2026-10-19T12:00:00Z",
        truncated: true, warnings: ["partial"],
      });
    },
  ) });
  try {
    assert.deepEqual(await manager.getDiagnosticContext("sbx-1"), context);
    for (const kind of ["Logs", "Events"]) {
      const result = await manager[`getDiagnostic${kind}`]("sbx-1", "all");
      assert.equal(result.delivery, "url");
      assert.equal(result.expiresAt.toISOString(), "2026-10-19T12:00:00.000Z");
      assert.deepEqual(result.warnings, ["partial"]);
      assert.equal(result.truncated, true);
    }
    assert.equal(calls.length, 3); // No execd connection or download of contentUrl.
  } finally { await manager.close(); }
});

test("sandbox diagnostics delegates through the injected lifecycle stack", async () => {
  const calls = [];
  const diagnostic = {
    getContext: async (id) => { calls.push([id]); return context; },
    getLogs: async (...args) => { calls.push(args); return {}; },
    getEvents: async (...args) => { calls.push(args); return {}; },
  };
  const config = new ConnectionConfig({ domain: "localhost:8080" });
  const sandbox = await Sandbox.connect({
    sandboxId: "sbx-1", connectionConfig: config, skipHealthCheck: true,
    adapterFactory: {
      createLifecycleStack: () => ({
        sandboxes: { getSandboxEndpoint: async () => ({ endpoint: "localhost:44772" }) },
        diagnostics: diagnostic,
      }),
      createExecdStack: () => ({ commands: {}, files: {}, health: {}, metrics: {} }),
      createEgressStack: () => ({ egress: {} }),
    },
  });
  try {
    assert.deepEqual(await sandbox.getDiagnosticContext(), context);
    await sandbox.getDiagnosticLogs("container");
    await sandbox.getDiagnosticEvents("runtime");
    assert.deepEqual(calls, [["sbx-1"], ["sbx-1", "container"], ["sbx-1", "runtime"]]);
  } finally { await sandbox.close(); }
});

test("context preserves API errors", async () => {
  for (const status of [403, 404, 501]) {
    const manager = SandboxManager.create({ connectionConfig: mockConfig(
      async () => Response.json(
        { code: "TEST_ERROR", message: "Unavailable" }, { status, headers: { "x-request-id": "request-1" } },
      ),
    ) });
    try {
      await assert.rejects(manager.getDiagnosticContext("sbx-1"), (error) =>
        error instanceof SandboxApiException && error.statusCode === status && error.requestId === "request-1");
    } finally { await manager.close(); }
  }
});

