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

import pytest
from fastapi import HTTPException

from app.query_params import parse_archive_max_bytes, parse_query_int


def test_parse_query_int_defaults_and_clamps():
    assert parse_query_int(None, field="limit", default=100, maximum=500) == 100
    assert parse_query_int("", field="limit", default=100, maximum=500) == 100
    assert parse_query_int("0", field="limit", default=100, minimum=1, maximum=500) == 1
    assert parse_query_int("9999", field="limit", default=100, maximum=500) == 500


def test_parse_query_int_rejects_garbage():
    with pytest.raises(HTTPException) as exc:
        parse_query_int("abc", field="limit", default=100, maximum=500)
    assert exc.value.detail["code"] == "INVALID_QUERY"


def test_parse_archive_max_bytes_clamps_to_cap():
    assert parse_archive_max_bytes(None, cap=512_288) == 512_288
    assert parse_archive_max_bytes("9999999", cap=512_288) == 512_288
    assert parse_archive_max_bytes("0", cap=512_288) == 1
    assert parse_archive_max_bytes("-5", cap=512_288) == 1
