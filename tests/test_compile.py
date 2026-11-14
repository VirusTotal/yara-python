#
# Copyright (c) 2007-2026. The YARA Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import io

import pytest
import yara


def test_compile_from_advanced_file_object_small(tmp_path):
    """Rules should not be lost when the file object was read from before compile()."""
    rule_file = tmp_path / "rules.yar"
    rule_file.write_text(
        "// header\n"
        "rule rule_alpha { condition: true }\n"
        "rule rule_beta  { condition: true }\n"
    )

    with open(rule_file, "r") as fp:
        fp.readline()
        rules = yara.compile(file=fp)

    identifiers = [r.identifier for r in rules]
    assert identifiers == ["rule_alpha", "rule_beta"], (
        f"expected all rules to compile; got {identifiers}"
    )


def test_compile_from_advanced_file_object_large(tmp_path):
    """Partial rule loss should not occur for files larger than the buffer size."""
    header = "// header\n"
    rule_a = "rule rule_alpha { condition: true }\n"
    padding_len = 8192 - len(header) - len(rule_a)
    padding = " " * padding_len
    rule_b = "rule rule_beta { condition: true }\n"
    rule_file = tmp_path / "rules.yar"
    rule_file.write_text(header + rule_a + padding + rule_b)

    with open(rule_file, "r") as fp:
        fp.readline()
        rules = yara.compile(file=fp)

    identifiers = [r.identifier for r in rules]
    assert identifiers == ["rule_alpha", "rule_beta"], (
        f"expected all rules to compile; got {identifiers}"
    )


def test_compile_from_bytesio():
    """file= should accept any object with a .read() method."""
    import io
    source = b"rule r { condition: true }"
    rules = yara.compile(file=io.BytesIO(source))
    assert [r.identifier for r in rules] == ["r"]
