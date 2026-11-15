from types import SimpleNamespace
from unittest.mock import patch

import netifaces
import pytest

from nxc.parsers.ip import get_local_ips, parse_targets, process_targets


class TestGetLocalIPs:
    @patch("netifaces.interfaces")
    @patch("netifaces.ifaddresses")
    def test_returns_nonlocal_ipv4_and_ipv6_addresses(self, mock_ifaddresses, mock_interfaces):
        mock_interfaces.return_value = ["lo", "eth0"]
        mock_ifaddresses.return_value = {
            netifaces.AF_INET: [{"addr": "192.168.1.100"}],
            netifaces.AF_INET6: [{"addr": "2001:db8::100"}],
        }

        assert get_local_ips() == {"192.168.1.100", "2001:db8::100"}
        mock_ifaddresses.assert_called_once_with("eth0")

    @patch("netifaces.interfaces")
    @patch("netifaces.ifaddresses")
    def test_skips_loopback_and_link_local_addresses(self, mock_ifaddresses, mock_interfaces):
        mock_interfaces.return_value = ["lo0", "eth0"]
        mock_ifaddresses.return_value = {
            netifaces.AF_INET: [{"addr": "127.0.0.1"}, {"addr": "169.254.1.1"}],
            netifaces.AF_INET6: [{"addr": "::1"}, {"addr": "fe80::1"}],
        }

        assert get_local_ips() == set()
        mock_ifaddresses.assert_called_once_with("eth0")


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("192.168.1.10", ["192.168.1.10"]),
        ("192.168.1.0/30", ["192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3"]),
        ("192.168.1.10-192.168.1.12", ["192.168.1.10", "192.168.1.11", "192.168.1.12"]),
        ("192.168.1.10-12", ["192.168.1.10", "192.168.1.11", "192.168.1.12"]),
        ("2001:db8::1", ["2001:db8::1"]),
        ("host.example", ["host.example"]),
    ],
)
def test_parse_targets(target, expected):
    assert list(parse_targets(target)) == expected


class TestProcessTargets:
    @patch("nxc.parsers.ip.skip_self", False)
    @patch("nxc.parsers.ip.exclude_hosts", [])
    def test_filters_cli_exclusions(self):
        args = SimpleNamespace(target=["192.168.1.0/30"], exclude_hosts=["192.168.1.1"], skip_self=False)

        assert process_targets(args) == ["192.168.1.0", "192.168.1.2", "192.168.1.3"]

    @patch("nxc.parsers.ip.get_local_ips", return_value={"192.168.1.2"})
    @patch("nxc.parsers.ip.skip_self", False)
    @patch("nxc.parsers.ip.exclude_hosts", [])
    def test_filters_local_addresses_when_requested(self, mock_get_local_ips):
        args = SimpleNamespace(target=["192.168.1.1-3"], exclude_hosts=None, skip_self=True)

        assert process_targets(args) == ["192.168.1.1", "192.168.1.3"]
        mock_get_local_ips.assert_called_once_with()

    @patch("nxc.parsers.ip.skip_self", False)
    @patch("nxc.parsers.ip.exclude_hosts", ["invalid exclusion"])
    def test_rejects_non_ip_exclusions(self):
        args = SimpleNamespace(target=["192.168.1.1"], exclude_hosts=None, skip_self=False)

        with pytest.raises(SystemExit):
            process_targets(args)
