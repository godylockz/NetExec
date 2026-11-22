from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture(scope="module")
def rdp_class():
    spec = spec_from_file_location("rdp_protocol", Path(__file__).parents[1] / "nxc" / "protocols" / "rdp.py")
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.rdp


class Logger:
    def __init__(self):
        self.messages = []

    def fail(self, message):
        self.messages.append(message)


class Runner:
    def run(self, coroutine):
        raise AssertionError("execute_shell must not run after the RDP session disconnects")


def test_execute_reports_disconnected_session(rdp_class):
    protocol = SimpleNamespace(
        args=SimpleNamespace(execute="whoami", no_output=False),
        conn=SimpleNamespace(disconnected_evt=SimpleNamespace(is_set=lambda: True)),
        logger=Logger(),
        runner=Runner(),
        username="t.ellis",
    )

    assert rdp_class.execute(protocol) is None
    assert protocol.logger.messages == [
        "RDP session disconnected before command execution; -x/-X was not run"
    ]
