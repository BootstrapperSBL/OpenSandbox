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

from opensandbox_server.api.schema import SandboxLifecycle
from opensandbox_server.extensions import (
    ACCESS_RENEW_EXTEND_SECONDS_METADATA_KEY,
    access_renew_extend_seconds_from_lifecycle,
    apply_access_renew_extend_seconds_to_mapping,
    apply_extensions_to_mapping,
    extract_extensions_from_mapping,
)


def _lifecycle(extend_seconds: int | None) -> SandboxLifecycle:
    if extend_seconds is None:
        return SandboxLifecycle()
    return SandboxLifecycle(renewalPolicy={"extendSeconds": extend_seconds})


class TestAccessRenewExtendSecondsFromLifecycle:
    """lifecycle.renewalPolicy (OSEP-0009) is the structured opt-in; the
    deprecated extensions["access.renew.extend.seconds"] key has no dedicated
    test coverage anymore (deprecated, removed in 2.0)."""

    def test_none_lifecycle(self):
        assert access_renew_extend_seconds_from_lifecycle(None) is None

    def test_lifecycle_without_policy(self):
        assert access_renew_extend_seconds_from_lifecycle(_lifecycle(None)) is None

    def test_lifecycle_with_policy(self):
        assert access_renew_extend_seconds_from_lifecycle(_lifecycle(3600)) == 3600


class TestApplyAccessRenewExtendSecondsWithLifecycle:
    def test_lifecycle_value_written(self):
        m: dict[str, str] = {}
        apply_access_renew_extend_seconds_to_mapping(m, None, lifecycle=_lifecycle(3600))
        assert m == {ACCESS_RENEW_EXTEND_SECONDS_METADATA_KEY: "3600"}

    def test_noop_when_both_absent(self):
        m: dict[str, str] = {"x": "1"}
        apply_access_renew_extend_seconds_to_mapping(m, None, lifecycle=_lifecycle(None))
        assert m == {"x": "1"}


class TestExtensionsToAnnotations:
    """Extensions with opensandbox.extensions. prefix are propagated to annotations."""

    def test_single_extension_propagated(self):
        annotations: dict[str, str] = {}
        extensions = {"opensandbox.extensions.pool-ref": "my-pool"}
        apply_extensions_to_mapping(annotations, extensions)
        assert annotations == {"opensandbox.io/extensions.pool-ref": "my-pool"}

    def test_multiple_extensions_propagated(self):
        annotations: dict[str, str] = {}
        extensions = {
            "opensandbox.extensions.pool-ref": "my-pool",
            "opensandbox.extensions.custom-key": "custom-value",
        }
        apply_extensions_to_mapping(annotations, extensions)
        assert annotations == {
            "opensandbox.io/extensions.pool-ref": "my-pool",
            "opensandbox.io/extensions.custom-key": "custom-value",
        }

    def test_non_prefix_extension_not_propagated(self):
        annotations: dict[str, str] = {}
        extensions = {
            "poolRef": "my-pool",
            "other.key": "value",
        }
        apply_extensions_to_mapping(annotations, extensions)
        assert annotations == {}

    def test_mixed_extensions_propagated_only_prefix_keys(self):
        annotations: dict[str, str] = {}
        extensions = {
            "opensandbox.extensions.pool-ref": "my-pool",
            "poolRef": "ignored",
        }
        apply_extensions_to_mapping(annotations, extensions)
        assert annotations == {"opensandbox.io/extensions.pool-ref": "my-pool"}

    def test_empty_extensions_noop(self):
        annotations: dict[str, str] = {"existing": "value"}
        apply_extensions_to_mapping(annotations, None)
        assert annotations == {"existing": "value"}

    def test_empty_extensions_dict_noop(self):
        annotations: dict[str, str] = {"existing": "value"}
        apply_extensions_to_mapping(annotations, {})
        assert annotations == {"existing": "value"}

    def test_preserves_existing_annotations(self):
        annotations: dict[str, str] = {"existing": "value"}
        extensions = {"opensandbox.extensions.new-key": "new-value"}
        apply_extensions_to_mapping(annotations, extensions)
        assert annotations == {
            "existing": "value",
            "opensandbox.io/extensions.new-key": "new-value",
        }


class TestExtensionsFromAnnotations:
    def test_restores_prefixed_annotations(self):
        annotations = {
            "opensandbox.io/extensions.custom-key": "custom-value",
            "opensandbox.io/extensions.localized": "中文数据",
        }

        assert extract_extensions_from_mapping(annotations) == {
            "opensandbox.extensions.custom-key": "custom-value",
            "opensandbox.extensions.localized": "中文数据",
        }

    def test_ignores_non_extension_annotations(self):
        annotations = {
            "opensandbox.io/access-renew-extend-seconds": "1800",
            "other": "value",
        }

        assert extract_extensions_from_mapping(annotations) is None

    def test_empty_annotations_return_none(self):
        assert extract_extensions_from_mapping({}) is None
        assert extract_extensions_from_mapping(None) is None
