from sys import exit

from impacket.dcerpc.v5 import drsuapi
from impacket.examples.secretsdump import RemoteOperations
from ldap3.utils.conv import escape_filter_chars

from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes


class NXCModule:
    name = "dcsync"
    description = "Check potential DCSync access, optionally probing replication of the authenticated account"
    supported_protocols = ["smb", "ldap"]
    category = CATEGORY.ENUMERATION

    def options(self, context, module_options):
        """
        Default checks report account/group hints, not effective replication permissions.
        LDAP checks nested membership and primary groups; SMB checks DC account/admin hints.

        PROBE    Confirm access with one DRSGetNCChanges request (SMB only, default: False).
                 Requests secret attributes for the authenticated account; does not print or save them.
                 Generates replication traffic and may generate directory-service audit events.
        """
        self.probe = module_options.get("PROBE", "false").lower() in ("true", "1", "yes")
        if self.probe and context.protocol != "smb":
            context.log.fail("PROBE requires SMB; use netexec smb -M dcsync -o PROBE=True")
            exit(1)

    def on_login(self, context, connection):
        if not connection.username:
            context.log.fail("An authenticated account is required")
            return
        if context.protocol == "ldap":
            self.check_ldap(context, connection)
            return
        if connection.args.local_auth:
            context.log.fail("DCSync checks require a domain account")
            return

        isdc = connection.is_host_dc()
        if isdc is False:
            context.log.display("Target is not a domain controller")
            return
        if self.probe:
            self.probe_replication(context, connection)
        elif isdc is None:
            context.log.fail("Could not determine whether the target is a domain controller")
        elif connection.username.endswith("$") and connection.username[:-1].casefold() == connection.hostname.casefold() and connection.domain and connection.domain.casefold() in (connection.targetDomain.casefold(), connection.conn.getServerDomain().casefold()):
            context.log.highlight("Potential DCSync access: account matches the DC machine name; replication permissions not verified")
        elif connection.admin_privs:
            context.log.highlight("Potential DCSync access: administrator on a DC; replication permissions not verified")
        else:
            context.log.display("No default DCSync account/admin hint found; delegated permissions were not checked")

    def check_ldap(self, context, connection):
        domain = parse_result_attributes(connection.search("(objectClass=domainDNS)", ["objectSid"], baseDN=connection.baseDN))
        if not domain or not domain[0].get("objectSid"):
            context.log.fail("Could not retrieve the domain SID")
            return
        domain_sid = escape_filter_chars(domain[0]["objectSid"])
        groups = parse_result_attributes(connection.search(
            f"(|(objectSid={domain_sid}-512)(objectSid={domain_sid}-519)(objectSid={domain_sid}-516)(objectSid=S-1-5-32-544))",
            ["distinguishedName"],
            baseDN=connection.baseDN,
        ))
        membership = [f"(memberOf:1.2.840.113556.1.4.1941:={escape_filter_chars(group['distinguishedName'])})" for group in groups if group.get("distinguishedName")]
        membership.extend(f"(primaryGroupID={rid})" for rid in (512, 519, 516))
        accounts = parse_result_attributes(connection.search(
            f"(&(sAMAccountName={escape_filter_chars(connection.username)})(|{''.join(membership)}))",
            ["distinguishedName", "msDS-PrincipalName"],
            baseDN=connection.baseDN,
        ))
        if accounts:
            if not connection.domain or (connection.domain.casefold() != connection.targetDomain.casefold() and accounts[0].get("msDS-PrincipalName", "").casefold() != f"{connection.domain}\\{connection.username}".casefold()):
                context.log.fail("Could not match the LDAP account to the authentication domain; use the target domain's DNS name for this check")
                return
            context.log.highlight("Potential DCSync access: default replication-capable group membership; effective permissions not verified")
        else:
            context.log.display("No default DCSync group membership found; delegated permissions were not checked")

    def probe_replication(self, context, connection):
        remote_ops = None
        try:
            netbios_domain = connection.conn.getServerDomain()
            dns_domain = connection.targetDomain
            if not connection.domain or connection.domain.casefold() not in (netbios_domain.casefold(), dns_domain.casefold()):
                context.log.fail("Probe requires an account from the target DC's domain")
                return
            remote_ops = RemoteOperations(connection.conn, connection.kerberos, connection.kdcHost)
            crack = remote_ops.DRSCrackNames(
                formatOffered=drsuapi.DS_NAME_FORMAT.DS_NT4_ACCOUNT_NAME if netbios_domain else drsuapi.DS_NT4_ACCOUNT_NAME_SANS_DOMAIN,
                formatDesired=drsuapi.DS_NAME_FORMAT.DS_UNIQUE_ID_NAME,
                name=f"{netbios_domain}\\{connection.username}" if netbios_domain else connection.username,
            )
            result = crack["pmsgOut"]["V1"]["pResult"]
            if result["cItems"] != 1 or result["rItems"][0]["status"] != 0:
                context.log.fail("Could not resolve the authenticated account GUID")
                return
            response = remote_ops.DRSGetNCChangesGuid(result["rItems"][0]["pName"].rstrip("\x00"))
            version = response["pdwOutVersion"]
            if version not in (6, 9):
                context.log.fail(f"Cannot verify replication response version {version}")
                return
            reply = response["pmsgOut"][f"V{version}"]
            if reply["dwDRSError"] or reply["ulExtendedRet"] != drsuapi.EXOP_ERR.EXOP_ERR_SUCCESS or reply["cNumObjects"] != 1:
                context.log.fail("Replication returned an error or no single account object; DCSync access not confirmed")
                return
            context.log.highlight("DCSync access confirmed: secret-attribute replication request for the authenticated account succeeded")
        except drsuapi.DCERPCSessionError as e:
            if e.get_error_code() in (5, 0x2105):
                context.log.fail("DCSync probe denied: replication access was denied")
            else:
                context.log.fail(f"DCSync probe failed; permissions not determined: {e}")
        except Exception as e:
            context.log.fail(f"DCSync probe failed; permissions not determined: {e}")
        finally:
            if remote_ops is not None:
                try:
                    remote_ops.finish()
                except Exception as e:
                    context.log.fail(f"Could not close DRSUAPI connection: {e}")
