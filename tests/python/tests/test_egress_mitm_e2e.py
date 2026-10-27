#
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
#
"""Egress x transparent-MITM interaction E2E (docker runtime, dns+nft).

Regressions for the class of bugs where the transparent MITM REDIRECT (the
destination is rewritten to the mitmproxy listener port before the nft egress
chain runs) is judged as if the workload had dialed the listener itself, so
every intercepted HTTPS flow is silently blackholed even when the policy
allows the original destination port:

- Scenario A: operator port floor (``reachable.ports.cap`` with only 80/443)
  plus Credential Vault (transparent MITM) with a default-allow policy —
  HTTPS must still work, and non-whitelisted ports must stay blocked
  (issue #2423).
- Scenario B: no floor, plus an allow-443/deny-all user policy with
  Credential Vault enabled — HTTPS must still work through the default-deny
  tail instead of dying on the rewritten port.

The floor file is injected into the sandbox's egress sidecar via
``docker exec`` (docker runtime only) and takes effect through the sidecar's
periodic always-rules reload (~1 minute), which the test polls for. The tests
are env-gated on ``OPENSANDBOX_EGRESS_MITM_E2E_TARGET_IP``, set by
``scripts/egress-mitm-e2e-target.sh`` (wired into ``scripts/python-e2e.sh``);
without it they skip.
"""

from __future__ import annotations

import os
import subprocess
import time
from datetime import timedelta

import pytest
from opensandbox import SandboxSync
from opensandbox.models.sandboxes import (
    CredentialProxyConfig,
    NetworkPolicy,
    NetworkRule,
    SandboxImageSpec,
)

from tests.base_e2e_test import (
    create_connection_config_sync,
    get_e2e_sandbox_resource,
    get_sandbox_image,
    is_kubernetes_runtime,
)

TARGET_IP = os.getenv("OPENSANDBOX_EGRESS_MITM_E2E_TARGET_IP", "")
E2E_LABEL_KEY = os.getenv(
    "OPENSANDBOX_EGRESS_MITM_E2E_LABEL_KEY", "opensandbox.e2e"
)
E2E_LABEL_VALUE = os.getenv(
    "OPENSANDBOX_EGRESS_MITM_E2E_LABEL_VALUE", "egress-mitm"
)
# The probe target listens here; the port is deliberately NOT 80/443 so it is
# neither MITM-intercepted nor whitelisted by the port floor.
PROBE_PORT = 8080
# The sidecar reloads operator rule files at most once per minute; poll a bit
# beyond that before concluding the floor never took effect.
FLOOR_RELOAD_TIMEOUT_S = 150


@pytest.fixture(scope="module")
def mitm_target_ip() -> str:
    if not TARGET_IP:
        pytest.skip("Set OPENSANDBOX_EGRESS_MITM_E2E_TARGET_IP to run this E2E")
    if is_kubernetes_runtime():
        pytest.skip("floor injection uses docker exec into the egress sidecar")
    return TARGET_IP


@pytest.mark.timeout(420)
def test_port_floor_with_vault_keeps_https_working(
    mitm_target_ip: str,
) -> None:
    """Issue #2423: reachable.ports.cap (80/443) + vault must not blackhole HTTPS.

    The floor complement is derived from whitelisted ports, but the MITM
    REDIRECT rewrites an intercepted SYN's destination port to the mitmproxy
    listener (e.g. 18081) before the nft chain evaluates it — which lands in
    the complement. Pre-fix, every intercepted HTTPS flow timed out even
    though 443 is whitelisted and the policy is default-allow.
    """
    cfg, sandbox = _create_sandbox(
        network_policy=NetworkPolicy(defaultAction="allow"),
    )
    try:
        _write_reachable_ports_cap(sandbox.id, ["80", "443"])

        # Phase 1 — precondition: the probe target is reachable before the
        # floor lands (it listens, the policy is default-allow).
        assert _wait_until_tcp(
            sandbox, mitm_target_ip, PROBE_PORT, expect_connected=True, timeout_s=60
        ), f"probe target {mitm_target_ip}:{PROBE_PORT} unreachable even before the floor"

        # Phase 2 — the injected cap file takes effect via the sidecar's
        # periodic always-rules reload (~1 minute): the non-whitelisted port
        # must flip to blocked.
        assert _wait_until_tcp(
            sandbox, mitm_target_ip, PROBE_PORT, expect_connected=False
        ), (
            "reachable.ports.cap floor did not take effect: a non-whitelisted "
            f"port ({PROBE_PORT}) stayed reachable under a default-allow policy; "
            "the sidecar either never reloaded the injected cap file or the floor is not enforced"
        )

        _assert_https_via_mitm(sandbox, "https://example.com", "Example Domain")
    finally:
        _close_sandbox(cfg, sandbox)


@pytest.mark.timeout(360)
def test_allow_443_deny_all_with_vault_keeps_https_working(
    mitm_target_ip: str,
) -> None:
    """allow-443/deny-all + transparent MITM must let HTTPS out.

    Pre-fix, the MITM REDIRECT rewrote the SYN's dport 443 to the listener
    port, which matches no allow rule, so the final default-deny drop
    blackholed every intercepted flow even though the user explicitly allowed
    443. Enforcement must also stay intact: a port the policy does not allow
    stays blocked.
    """
    cfg, sandbox = _create_sandbox(
        network_policy=NetworkPolicy(
            defaultAction="deny",
            egress=[NetworkRule(action="allow", ports=[443])],
        ),
    )
    try:
        # Gate: the MITM path is live at all. Pre-fix this connect timed out
        # because the rewritten dport hit the default-deny drop before
        # mitmproxy ever saw the flow.
        assert _wait_until_tcp(
            sandbox, "1.1.1.1", 443, expect_connected=True, timeout_s=60
        ), "TCP/443 was blackholed by the MITM redirect under allow-443/deny-all"

        # The probe target listens on PROBE_PORT, so the block below proves
        # the deny-all default really bites (not just "nothing there").
        assert _wait_until_tcp(
            sandbox, mitm_target_ip, PROBE_PORT, expect_connected=False, timeout_s=45
        ), "deny-all policy did not block a non-allowed port"

        _assert_https_via_mitm(
            sandbox,
            (
                "'https://cloudflare-dns.com/dns-query?name=example.com&type=A'"
                " --resolve cloudflare-dns.com:443:1.1.1.1"
                " --header 'accept: application/dns-json'"
            ),
            '"Status":0',
        )
    finally:
        _close_sandbox(cfg, sandbox)


def _create_sandbox(network_policy: NetworkPolicy) -> tuple[object, SandboxSync]:
    cfg = create_connection_config_sync()
    sandbox = SandboxSync.create(
        image=SandboxImageSpec(get_sandbox_image()),
        resource=get_e2e_sandbox_resource(),
        connection_config=cfg,
        timeout=timedelta(minutes=5),
        ready_timeout=timedelta(seconds=60),
        network_policy=network_policy,
        credential_proxy=CredentialProxyConfig(enabled=True),
        metadata={E2E_LABEL_KEY: E2E_LABEL_VALUE},
    )
    return cfg, sandbox


def _close_sandbox(cfg: object, sandbox: SandboxSync) -> None:
    try:
        sandbox.kill()
    finally:
        sandbox.close()
        try:
            cfg.transport.close()
        except Exception:
            # Best-effort teardown: do not fail the test if transport is already closed
            # or cannot be closed during cleanup.
            pass


def _write_reachable_ports_cap(sandbox_id: str, ports: list[str]) -> None:
    """Inject the operator port floor into this sandbox's egress sidecar.

    The sidecar re-reads /var/egress rules periodically (~1 minute) and
    re-applies the nft static policy, so the floor takes effect without a
    restart.
    """
    body = "\\n".join(ports) + "\\n"
    _sidecar_exec(
        sandbox_id,
        "mkdir -p /var/egress/rules && "
        f"printf '{body}' > /var/egress/rules/reachable.ports.cap && "
        "cat /var/egress/rules/reachable.ports.cap",
    )


def _sidecar_exec(sandbox_id: str, script: str) -> str:
    container = f"sandbox-egress-{sandbox_id}"
    result = subprocess.run(
        ["docker", "exec", container, "sh", "-c", script],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, (
        f"docker exec {container} failed: "
        f"{result.stderr.strip() or result.stdout.strip()}"
    )
    return result.stdout


def _tcp_connects(sandbox: SandboxSync, host: str, port: int) -> bool:
    probe = sandbox.commands.run(
        f"timeout 6 bash -c 'echo > /dev/tcp/{host}/{port}' 2>/dev/null"
    )
    return probe.error is None and probe.exit_code == 0


def _wait_until_tcp(
    sandbox: SandboxSync,
    host: str,
    port: int,
    *,
    expect_connected: bool,
    timeout_s: int = FLOOR_RELOAD_TIMEOUT_S,
) -> bool:
    """Poll the TCP probe until it matches the expectation, or give up.

    Covers sidecar startup ordering (nft apply, MITM readiness) and the
    always-rules reload latency without fixed sleeps.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _tcp_connects(sandbox, host, port) == expect_connected:
            return True
        time.sleep(5)
    return False


def _assert_https_via_mitm(sandbox: SandboxSync, url_and_args: str, expect: str) -> None:
    """Assert a real HTTPS request succeeds through the MITM path, with retries.

    TLS verification stays ON: the sandbox trusts the mitm CA installed by the
    execd bootstrap, and mitmproxy verifies the upstream against public roots.
    """
    last = ""
    for _ in range(3):
        result = sandbox.commands.run(
            f"curl --silent --show-error --connect-timeout 8 --max-time 25 {url_and_args}"
        )
        stdout = "".join(part.text for part in result.logs.stdout)
        if result.error is None and result.exit_code == 0 and expect in stdout:
            return
        last = str(result.error) if result.error else f"exit={result.exit_code} stdout={stdout!r}"
        time.sleep(5)
    pytest.fail(f"HTTPS through the MITM did not succeed: {last}")
