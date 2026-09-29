import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from nxc.helpers.misc import normalize_ntlm_hash, validate_ntlm


NT_HASH = "0123456789abcdef0123456789abcdef"
LM_HASH = "fedcba9876543210fedcba9876543210"


@pytest.mark.parametrize(("value", "expected"), [
    (NT_HASH, NT_HASH),
    (NT_HASH.upper(), NT_HASH.upper()),
    (f":{NT_HASH}", NT_HASH),
    (f"{LM_HASH}:{NT_HASH}", f"{LM_HASH}:{NT_HASH}"),
    (f" \t:{NT_HASH}\r\n", NT_HASH),
])
def test_supported_hash_formats(value, expected):
    assert normalize_ntlm_hash(value) == expected


@pytest.mark.parametrize("value", [
    "", " ", "z" * 32, "a" * 31, "a" * 33, f"{NT_HASH}:xyz",
    f"prefix:{NT_HASH}", f"prefix:extra:{NT_HASH}", f"::{NT_HASH}",
    f":{LM_HASH}:{NT_HASH}", f"{'z' * 32}:{NT_HASH}", f"{LM_HASH}:{'z' * 32}",
    f"{LM_HASH}:", f"{NT_HASH}:suffix", f"{NT_HASH[:16]}:{NT_HASH[16:]}",
])
def test_invalid_hash_formats(value):
    assert normalize_ntlm_hash(value) is None


@pytest.mark.parametrize("value", [NT_HASH, NT_HASH.upper()])
def test_validate_ntlm_accepts_exact_hex(value):
    assert validate_ntlm(value)


@pytest.mark.parametrize("value", ["", "z" * 32, NT_HASH + "suffix", NT_HASH + "\n", f"{LM_HASH}:{NT_HASH}"])
def test_validate_ntlm_rejects_partial_matches(value):
    assert not validate_ntlm(value)


@pytest.fixture
def parse_hashes(tmp_path):
    # Import the real parser in a process whose configuration is isolated from the host.
    root = Path(__file__).resolve().parents[1]
    config = tmp_path / "config"
    config.mkdir()
    (config / "nxc.conf").write_bytes((root / "nxc/data/nxc.conf").read_bytes())
    program = """
import json
import sys
from types import SimpleNamespace
from unittest.mock import Mock
from nxc.connection import connection

client = connection.__new__(connection)
client.args = SimpleNamespace(username=["testuser"], password=[], hash=json.load(sys.stdin), domain="example.test", aesKey=[])
client.domain = "example.test"
client.logger = Mock()
try:
    result = client.parse_credentials()
    print(json.dumps({"hashes": result[3], "types": result[4], "failures": client.logger.fail.call_count}))
except SystemExit as e:
    print(json.dumps({"exit": e.code, "failures": client.logger.fail.call_count}))
"""

    def parse(values):
        result = subprocess.run(
            [sys.executable, "-c", program], input=json.dumps(values), text=True, capture_output=True,
            env={**os.environ, "NXC_PATH": str(config)}, cwd=root, check=True, timeout=30,
        )
        return json.loads(result.stdout)

    return parse


@pytest.mark.parametrize(("value", "expected"), [(NT_HASH, NT_HASH), (f":{NT_HASH}", NT_HASH), (f"{LM_HASH}:{NT_HASH}", f"{LM_HASH}:{NT_HASH}")])
def test_cli_hash_parser_preserves_supported_formats(parse_hashes, value, expected):
    assert parse_hashes([value]) == {"hashes": [expected], "types": ["hash"], "failures": 0}


def test_cli_hash_parser_rejects_invalid_input(parse_hashes):
    assert parse_hashes([f"extra:{NT_HASH}"]) == {"exit": 1, "failures": 1}


def test_hash_file_parser_skips_invalid_and_blank_lines(parse_hashes, tmp_path):
    hashes = tmp_path / "hashes.txt"
    hashes.write_text(f"\n:{NT_HASH}\nextra:{NT_HASH}\n{LM_HASH}:{NT_HASH}\n\n")
    assert parse_hashes([str(hashes)]) == {"hashes": [NT_HASH, f"{LM_HASH}:{NT_HASH}"], "types": ["hash", "hash"], "failures": 1}
