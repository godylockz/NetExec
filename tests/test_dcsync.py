"""Offline DCSync module regressions; all network operations are mocked."""

from types import SimpleNamespace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main
from unittest.mock import Mock, patch

from impacket.dcerpc.v5 import drsuapi
from impacket.ldap.ldapasn1 import SearchResultEntry
from impacket.ldap.ldaptypes import LDAP_SID

from nxc.modules.dcsync import NXCModule
from nxc.context import Context
from nxc.loaders.moduleloader import ModuleLoader


def ldap_entry(attributes):
    entry = SearchResultEntry()
    entry["objectName"] = "DC=example,DC=test"
    for index, (name, value) in enumerate(attributes.items()):
        entry["attributes"][index]["type"] = name
        if name == "objectSid":
            sid = LDAP_SID()
            sid.fromCanonical(value)
            value = sid.getData()
        entry["attributes"][index]["vals"][0] = value
    return entry


def crack_response(count=1, status=0):
    response = drsuapi.DRSCrackNamesResponse()
    response["pdwOutVersion"] = 1
    response["pmsgOut"]["tag"] = 1
    result = response["pmsgOut"]["V1"]["pResult"]
    result["cItems"] = count
    if count:
        item = drsuapi.DS_NAME_RESULT_ITEMW()
        item["status"] = status
        item["pName"] = "{00000000-0000-0000-0000-000000000001}\x00"
        result["rItems"].append(item)
    return response


def replication_response(version=6, count=1, error=0, extended=1):
    response = drsuapi.DRSGetNCChangesResponse()
    response["pdwOutVersion"] = version
    response["pmsgOut"]["tag"] = version
    reply = response["pmsgOut"][f"V{version}"]
    reply["cNumObjects"] = count
    reply["ulExtendedRet"] = extended
    if version in (6, 9):
        reply["dwDRSError"] = error
    return response


class DCSyncTests(TestCase):
    def setUp(self):
        config_directory = TemporaryDirectory(prefix="netexec-dcsync-test-")
        self.addCleanup(config_directory.cleanup)
        config_patch = patch("nxc.context.CONFIG_PATH", str(Path(config_directory.name) / "nxc.conf"))
        config_patch.start()
        self.addCleanup(config_patch.stop)
        self.context = Context(None, Mock(), SimpleNamespace(protocol="smb"))
        self.connection = SimpleNamespace(
            username="testuser", hostname="TESTDC", domain="example.test", targetDomain="example.test",
            admin_privs=False, kerberos=False, kdcHost=None, conn=Mock(),
            args=SimpleNamespace(local_auth=False), is_host_dc=Mock(return_value=True),
            baseDN="DC=example,DC=test", search=Mock(),
        )
        self.connection.conn.getServerDomain.return_value = "EXAMPLE"
        self.module = NXCModule()
        self.module.options(self.context, {})
        self.remote = Mock()
        self.remote.DRSCrackNames.return_value = crack_response()
        self.remote.DRSGetNCChangesGuid.return_value = replication_response()
        remote_patch = patch("nxc.modules.dcsync.RemoteOperations", return_value=self.remote)
        self.remote_factory = remote_patch.start()
        self.addCleanup(remote_patch.stop)

    def use_probe(self):
        self.module.options(self.context, {"PROBE": "True"})

    def use_ldap(self, account=True, groups=True):
        self.context.protocol = "ldap"
        self.connection.search.side_effect = [
            [ldap_entry({"objectSid": "S-1-5-21-100-200-300"})],
            [ldap_entry({"distinguishedName": "CN=Domain Admins,DC=example,DC=test"})] if groups else [],
            [ldap_entry({"distinguishedName": "CN=Test Account,DC=example,DC=test", "msDS-PrincipalName": "EXAMPLE\\testuser"})] if account else [],
        ]

    def test_default_does_not_replicate(self):
        self.module.on_login(self.context, self.connection)
        self.remote_factory.assert_not_called()
        self.context.log.highlight.assert_not_called()

    def test_same_named_user_is_not_machine_account(self):
        self.connection.username = "testdc"
        self.module.on_login(self.context, self.connection)
        self.context.log.highlight.assert_not_called()

    def test_dc_machine_account_is_only_a_hint(self):
        self.connection.username = "testdc$"
        self.module.on_login(self.context, self.connection)
        self.assertIn("not verified", self.context.log.highlight.call_args.args[0])
        self.remote_factory.assert_not_called()
        self.assertFalse(hasattr(self.connection, "dcsync_privs"))

    def test_admin_is_only_a_hint(self):
        self.connection.admin_privs = True
        self.module.on_login(self.context, self.connection)
        self.assertIn("not verified", self.context.log.highlight.call_args.args[0])
        self.remote_factory.assert_not_called()

    def test_foreign_machine_account_is_not_a_local_dc_hint(self):
        self.connection.username = "TESTDC$"
        self.connection.domain = "other.test"
        self.module.on_login(self.context, self.connection)
        self.context.log.highlight.assert_not_called()

    def test_dc_machine_hint_accepts_netbios_domain(self):
        self.connection.username = "TESTDC$"
        self.connection.domain = "example"
        self.module.on_login(self.context, self.connection)
        self.context.log.highlight.assert_called_once()

    def test_hint_is_not_retained_between_accounts(self):
        self.connection.username = "TESTDC$"
        self.module.on_login(self.context, self.connection)
        self.context.log.reset_mock()
        self.connection.username = "testuser"
        self.module.on_login(self.context, self.connection)
        self.context.log.highlight.assert_not_called()

    def test_non_dc_skips_probe(self):
        self.use_probe()
        self.connection.is_host_dc.return_value = False
        self.module.on_login(self.context, self.connection)
        self.remote_factory.assert_not_called()

    def test_unknown_dc_is_not_a_positive_hint(self):
        self.connection.is_host_dc.return_value = None
        self.connection.admin_privs = True
        self.module.on_login(self.context, self.connection)
        self.context.log.highlight.assert_not_called()
        self.context.log.fail.assert_called_once()

    def test_explicit_probe_can_resolve_unknown_dc(self):
        self.use_probe()
        self.connection.is_host_dc.return_value = None
        self.module.on_login(self.context, self.connection)
        self.context.log.highlight.assert_called_once()

    def test_local_account_is_not_checked(self):
        self.use_probe()
        self.connection.args.local_auth = True
        self.module.on_login(self.context, self.connection)
        self.remote_factory.assert_not_called()
        self.connection.is_host_dc.assert_not_called()

    def test_anonymous_account_is_not_checked(self):
        self.connection.username = ""
        self.module.on_login(self.context, self.connection)
        self.connection.is_host_dc.assert_not_called()

    def test_ldap_nested_and_primary_membership_are_hints(self):
        self.use_ldap()
        self.module.on_login(self.context, self.connection)
        self.assertIn("not verified", self.context.log.highlight.call_args.args[0])
        query = self.connection.search.call_args.args[0]
        self.assertIn("memberOf:1.2.840.113556.1.4.1941", query)
        self.assertIn("(primaryGroupID=516)", query)
        self.assertNotIn("(primaryGroupID=521)", query)
        self.remote_factory.assert_not_called()

    def test_ldap_primary_group_checked_without_group_results(self):
        self.use_ldap(groups=False)
        self.module.on_login(self.context, self.connection)
        self.context.log.highlight.assert_called_once()
        self.assertIn("(primaryGroupID=516)", self.connection.search.call_args.args[0])

    def test_ldap_excludes_operator_groups(self):
        self.use_ldap(account=False)
        self.module.on_login(self.context, self.connection)
        queries = "".join(call.args[0] for call in self.connection.search.call_args_list)
        self.assertNotIn("-549", queries)
        self.assertNotIn("-551", queries)
        self.assertNotIn("primaryGroupID=549", queries)
        self.assertNotIn("primaryGroupID=551", queries)
        self.context.log.highlight.assert_not_called()

    def test_ldap_escapes_account_and_group_filter_values(self):
        self.use_ldap()
        self.connection.username = "test*)(objectClass=*)"
        self.connection.search.side_effect = [
            [ldap_entry({"objectSid": "S-1-5-21-100-200-300"})],
            [ldap_entry({"distinguishedName": "CN=Test (Group)*,DC=example,DC=test"})], [],
        ]
        self.module.on_login(self.context, self.connection)
        query = self.connection.search.call_args.args[0]
        self.assertIn(r"test\2a\29\28objectClass=\2a\29", query)
        self.assertIn(r"CN=Test \28Group\29\2a", query)

    def test_ldap_missing_domain_sid_reports_lookup_failure(self):
        self.use_ldap()
        self.connection.search.side_effect = [[]]
        self.module.on_login(self.context, self.connection)
        self.context.log.fail.assert_called_once()
        self.context.log.highlight.assert_not_called()

    def test_ldap_result_is_not_retained_between_accounts(self):
        self.use_ldap()
        self.module.on_login(self.context, self.connection)
        self.context.log.reset_mock()
        self.use_ldap(account=False)
        self.module.on_login(self.context, self.connection)
        self.context.log.highlight.assert_not_called()

    def test_ldap_does_not_match_same_named_account_from_another_domain(self):
        self.use_ldap()
        self.connection.domain = "other.test"
        self.module.on_login(self.context, self.connection)
        self.context.log.highlight.assert_not_called()
        self.context.log.fail.assert_called_once()

    def test_ldap_accepts_netbios_authentication_domain(self):
        self.use_ldap()
        self.connection.domain = "example"
        self.module.on_login(self.context, self.connection)
        self.context.log.highlight.assert_called_once()

    def test_ldap_unknown_account_domain_is_inconclusive(self):
        self.use_ldap()
        self.connection.domain = "example"
        self.connection.search.side_effect = [
            [ldap_entry({"objectSid": "S-1-5-21-100-200-300"})], [],
            [ldap_entry({"distinguishedName": "CN=Test Account,DC=example,DC=test"})],
        ]
        self.module.on_login(self.context, self.connection)
        self.context.log.highlight.assert_not_called()
        self.context.log.fail.assert_called_once()

    def test_ldap_probe_option_is_rejected(self):
        self.context.protocol = "ldap"
        with self.assertRaises(SystemExit) as raised:
            self.use_probe()
        self.assertEqual(raised.exception.code, 1)

    def test_probe_checks_one_own_account_and_closes_rpc(self):
        self.use_probe()
        self.module.on_login(self.context, self.connection)
        self.remote.DRSCrackNames.assert_called_once_with(
            formatOffered=drsuapi.DS_NAME_FORMAT.DS_NT4_ACCOUNT_NAME,
            formatDesired=drsuapi.DS_NAME_FORMAT.DS_UNIQUE_ID_NAME,
            name="EXAMPLE\\testuser",
        )
        self.remote.DRSGetNCChangesGuid.assert_called_once_with("{00000000-0000-0000-0000-000000000001}")
        self.remote.finish.assert_called_once()
        self.context.log.highlight.assert_called_once()

    def test_probe_preserves_kerberos_connection_settings(self):
        self.use_probe()
        self.connection.kerberos = True
        self.connection.kdcHost = "dc.example.test"
        self.module.on_login(self.context, self.connection)
        self.remote_factory.assert_called_once_with(self.connection.conn, True, "dc.example.test")

    def test_probe_resolves_netbios_login_domain(self):
        self.use_probe()
        self.connection.domain = "example"
        self.module.on_login(self.context, self.connection)
        self.context.log.highlight.assert_called_once()

    def test_probe_without_netbios_name_requires_matching_dns_domain(self):
        self.use_probe()
        self.connection.conn.getServerDomain.return_value = ""
        self.module.on_login(self.context, self.connection)
        self.remote.DRSCrackNames.assert_called_once_with(
            formatOffered=drsuapi.DS_NT4_ACCOUNT_NAME_SANS_DOMAIN,
            formatDesired=drsuapi.DS_NAME_FORMAT.DS_UNIQUE_ID_NAME,
            name="testuser",
        )
        self.context.log.highlight.assert_called_once()

    def test_probe_without_domain_does_not_resolve_an_ambiguous_account(self):
        self.use_probe()
        self.connection.domain = ""
        self.connection.targetDomain = ""
        self.connection.conn.getServerDomain.return_value = ""
        self.module.on_login(self.context, self.connection)
        self.remote_factory.assert_not_called()
        self.context.log.highlight.assert_not_called()

    def test_probe_does_not_resolve_same_named_foreign_account(self):
        self.use_probe()
        self.connection.domain = "other.test"
        self.module.on_login(self.context, self.connection)
        self.remote_factory.assert_not_called()
        self.context.log.highlight.assert_not_called()

    def test_admin_hint_does_not_bypass_explicit_probe(self):
        self.use_probe()
        self.connection.admin_privs = True
        self.remote.DRSGetNCChangesGuid.side_effect = drsuapi.DCERPCSessionError(error_code=0x2105)
        self.module.on_login(self.context, self.connection)
        self.context.log.highlight.assert_not_called()
        self.assertIn("denied", self.context.log.fail.call_args.args[0])
        self.remote.finish.assert_called_once()

    def test_name_lookup_failure_does_not_replicate(self):
        self.use_probe()
        for count, status in ((0, 0), (1, 2), (2, 0)):
            with self.subTest(count=count, status=status):
                self.remote.reset_mock()
                self.remote.DRSCrackNames.return_value = crack_response(count=count, status=status)
                self.module.on_login(self.context, self.connection)
                self.remote.DRSGetNCChangesGuid.assert_not_called()
                self.remote.finish.assert_called_once()
        self.context.log.highlight.assert_not_called()

    def test_error_empty_and_unsupported_responses_are_not_success(self):
        self.use_probe()
        for response in (replication_response(error=0x2105), replication_response(count=0), replication_response(count=2), replication_response(extended=2), replication_response(version=1)):
            with self.subTest(response=response):
                self.remote.DRSGetNCChangesGuid.return_value = response
                self.module.on_login(self.context, self.connection)
        self.context.log.highlight.assert_not_called()
        self.assertEqual(self.remote.finish.call_count, 5)

    def test_version_nine_response_is_supported(self):
        self.use_probe()
        self.remote.DRSGetNCChangesGuid.return_value = replication_response(version=9)
        self.module.on_login(self.context, self.connection)
        self.context.log.highlight.assert_called_once()

    def test_rpc_failure_is_not_reported_as_access_denied(self):
        self.use_probe()
        self.remote.DRSCrackNames.side_effect = OSError("test transport failure")
        self.module.on_login(self.context, self.connection)
        self.assertIn("not determined", self.context.log.fail.call_args.args[0])
        self.context.log.highlight.assert_not_called()
        self.remote.finish.assert_called_once()

    def test_probe_success_is_not_retained_between_accounts(self):
        self.use_probe()
        self.module.on_login(self.context, self.connection)
        self.context.log.reset_mock()
        self.connection.username = "seconduser"
        self.remote.DRSGetNCChangesGuid.side_effect = drsuapi.DCERPCSessionError(error_code=0x2105)
        self.module.on_login(self.context, self.connection)
        self.context.log.highlight.assert_not_called()
        self.assertFalse(hasattr(self.connection, "dcsync_privs"))

    def test_cleanup_failure_is_logged(self):
        self.use_probe()
        self.remote.finish.side_effect = OSError("test close failure")
        self.module.on_login(self.context, self.connection)
        self.assertIn("Could not close", self.context.log.fail.call_args.args[0])

    def test_real_loader_initializes_both_protocols(self):
        for protocol in ("smb", "ldap"):
            with self.subTest(protocol=protocol):
                args = SimpleNamespace(protocol=protocol, module_options=[])
                loader = ModuleLoader(args, None, self.context.log)
                module = loader.init_module(str(Path(__file__).resolve().parents[1] / "nxc" / "modules" / "dcsync.py"))
                self.assertIsNotNone(module)
                self.assertFalse(module.probe)

    def test_real_loader_initializes_probe(self):
        args = SimpleNamespace(protocol="smb", module_options=["PROBE=True"])
        loader = ModuleLoader(args, None, self.context.log)
        module = loader.init_module(str(Path(__file__).resolve().parents[1] / "nxc" / "modules" / "dcsync.py"))
        self.assertTrue(module.probe)


if __name__ == "__main__":
    main()
