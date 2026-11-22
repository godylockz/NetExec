from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest


@pytest.fixture(scope="module")
def winrm_module():
    spec = spec_from_file_location("winrm_protocol", Path(__file__).parents[1] / "nxc" / "protocols" / "winrm.py")
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Logger:
    def __init__(self):
        self.messages = []
        self.extra = {}

    def debug(self, message):
        self.messages.append(message)

    def info(self, message):
        self.messages.append(message)

    def success(self, message):
        self.messages.append(message)

    def fail(self, message):
        self.messages.append(message)


def test_check_if_admin_builds_wsman_enumeration(winrm_module):
    calls = []
    protocol = SimpleNamespace(
        admin_privs=False,
        conn=SimpleNamespace(
            wsman=SimpleNamespace(enumerate=lambda resource, message: calls.append((resource, message)))
        ),
    )

    assert winrm_module.winrm.check_if_admin(protocol) is True
    assert protocol.admin_privs is True
    assert calls[0][0] == "http://schemas.microsoft.com/wbem/wsman/1/windows/shell"
    assert calls[0][1].tag.endswith("Enumerate")


def test_kerberos_cache_login_uses_pypsrp(winrm_module):
    client_calls = []

    class Client:
        def __init__(self, host, **kwargs):
            client_calls.append((host, kwargs))

    protocol = SimpleNamespace(
        admin_privs=False,
        config={},
        db=SimpleNamespace(),
        domain="EXAMPLE.TEST",
        host="srv02.example.test",
        hostname="srv02.example.test",
        logger=Logger(),
        mark_pwned=lambda: "(Pwn3d!)",
        port=5985,
        ssl=False,
        targetDomain="EXAMPLE.TEST",
    )
    protocol.check_if_admin = lambda: setattr(protocol, "admin_privs", True)

    with (
        patch.object(winrm_module, "Client", Client),
        patch.object(winrm_module, "add_user_bh"),
    ):
        assert winrm_module.winrm.kerberos_login(
            protocol, "EXAMPLE.TEST", "alice", useCache=True
        ) is True

    assert client_calls == [(
        "srv02.example.test",
        {
            "port": 5985,
            "auth": "kerberos",
            "username": None,
            "password": None,
            "ssl": False,
            "cert_validation": False,
        },
    )]
    assert any("from ccache" in message for message in protocol.logger.messages)


def test_kerberos_login_rejects_unsupported_aes_key(winrm_module):
    protocol = SimpleNamespace(
        admin_privs=False,
        domain="EXAMPLE.TEST",
        logger=Logger(),
        targetDomain="EXAMPLE.TEST",
    )

    assert winrm_module.winrm.kerberos_login(
        protocol, "EXAMPLE.TEST", "alice", aesKey="00"
    ) is False
    assert "not NTLM hashes" in protocol.logger.messages[0]


def test_kerberos_enumeration_survives_missing_ntlm_challenge(winrm_module):
    protocol = SimpleNamespace(
        args=SimpleNamespace(domain="EXAMPLE.TEST", local_auth=False),
        challenge_header="Negotiate",
        domain=None,
        hostname="srv02.example.test",
        kerberos=True,
        logger=Logger(),
        no_ntlm=False,
        targetDomain=None,
    )

    assert winrm_module.winrm.enum_host_info(protocol) is None
    assert protocol.no_ntlm is True
    assert protocol.domain == "EXAMPLE.TEST"
