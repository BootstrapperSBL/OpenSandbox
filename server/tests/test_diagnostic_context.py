# Copyright 2026 The OpenSandbox Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from fastapi import HTTPException

from opensandbox_server.api import devops
from opensandbox_server.services.diagnostics import DiagnosticContext
from opensandbox_server.services.docker.docker_diagnostics import DockerDiagnosticsMixin
from opensandbox_server.services.k8s.k8s_diagnostics import K8sDiagnosticsMixin
from opensandbox_server.services.fast_sandbox.service import FastSandboxService
from opensandbox_server.services.composite_service import CompositeSandboxService
from opensandbox_server.services.sandbox_service import SandboxService


@pytest.mark.parametrize("backend", ["docker", "kubernetes", "fast-sandbox"])
def test_context_route(client, auth_headers, monkeypatch, backend):
    service = Mock()
    service.get_sandbox_diagnostic_context.return_value = DiagnosticContext(
        sandbox_id="sbx-1",
        state="Paused",
        backend_type=backend,
        backend_identifiers={"resource": "runtime-1"},
    )
    monkeypatch.setattr(devops, "sandbox_service", service)
    response = client.get("/v1/sandboxes/sbx-1/diagnostics/context", headers=auth_headers)
    assert response.status_code == 200
    assert response.json() == {
        "sandboxId": "sbx-1",
        "state": "Paused",
        "backendType": backend,
        "backendIdentifiers": {"resource": "runtime-1"},
    }
    service.get_sandbox_diagnostic_context.assert_called_once_with("sbx-1")


@pytest.mark.parametrize(
    "status,code", [(404, "NOT_FOUND"), (403, "FORBIDDEN"), (501, "DIAGNOSTICS_NOT_IMPLEMENTED")]
)
def test_context_route_preserves_backend_errors(client, auth_headers, monkeypatch, status, code):
    service = Mock()
    service.get_sandbox_diagnostic_context.side_effect = HTTPException(
        status,
        detail={"code": code, "message": "Unavailable"},
    )
    monkeypatch.setattr(devops, "sandbox_service", service)
    response = client.get("/v1/sandboxes/sbx-1/diagnostics/context", headers=auth_headers)
    assert response.status_code == status


def test_docker_context_uses_owned_container():
    service = DockerDiagnosticsMixin()
    service._get_container_by_sandbox_id = Mock(
        return_value=SimpleNamespace(id="container-1", name="sandbox-1")
    )
    service._container_to_sandbox = Mock(
        return_value=SimpleNamespace(status=SimpleNamespace(state="Paused"))
    )
    context = service.get_sandbox_diagnostic_context("sbx-1")
    assert context.backend_type == "docker"
    assert context.backend_identifiers == {
        "containerId": "container-1",
        "containerName": "sandbox-1",
    }
    service._get_container_by_sandbox_id.assert_called_once_with("sbx-1")


def test_kubernetes_context_is_available_before_pod_allocation(monkeypatch):
    service = K8sDiagnosticsMixin()
    service._resolve_namespace_for_lookup = Mock(return_value="tenant-ns")
    service.workload_provider = Mock()
    workload = {"metadata": {"name": "workload-1", "uid": "uid-1"}}
    owned = Mock(return_value=workload)
    monkeypatch.setattr(
        "opensandbox_server.services.k8s.k8s_diagnostics._get_owned_workload_or_404", owned
    )
    monkeypatch.setattr(
        "opensandbox_server.services.k8s.k8s_diagnostics._build_sandbox_from_workload",
        Mock(return_value=SimpleNamespace(status=SimpleNamespace(state="Pending"))),
    )
    context = service.get_sandbox_diagnostic_context("sbx-1")
    assert context.state == "Pending"
    assert context.backend_identifiers == {
        "namespace": "tenant-ns",
        "workloadName": "workload-1",
        "workloadUid": "uid-1",
    }
    owned.assert_called_once_with(service.workload_provider, "tenant-ns", "sbx-1")


def test_fast_context_uses_lifecycle_identity():
    service = Mock()
    service.get_sandbox.return_value = SimpleNamespace(status=SimpleNamespace(state="Running"))
    context = FastSandboxService.get_sandbox_diagnostic_context(service, "fsb-1")
    assert context.backend_type == "fast-sandbox"
    assert context.backend_identifiers == {}
    service.get_sandbox.assert_called_once_with("fsb-1")


@pytest.mark.parametrize("sandbox_id,backend", [("fsb-1", "fsb"), ("sbx-1", "kubernetes")])
def test_composite_routes_context(sandbox_id, backend):
    k8s, fsb = Mock(), Mock()
    service = CompositeSandboxService(k8s, fsb)
    expected = fsb if backend == "fsb" else k8s
    assert (
        service.get_sandbox_diagnostic_context(sandbox_id)
        is expected.get_sandbox_diagnostic_context.return_value
    )
    expected.get_sandbox_diagnostic_context.assert_called_once_with(sandbox_id)


def test_extension_context_defaults_to_not_implemented():
    with pytest.raises(HTTPException) as error:
        SandboxService.get_sandbox_diagnostic_context(Mock(), "sbx-1")
    assert error.value.status_code == 501
