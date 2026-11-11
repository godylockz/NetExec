#!/usr/bin/env python3
# -- coding: utf-8 --

# Imports
import pytest
from defusedxml.common import EntitiesForbidden

from nxc.modules.mremoteng import NXCModule as MRemoteNGModule
from nxc.modules.wds_mdt import NXCModule as WDSMDTModule


MALICIOUS_XML = b"""<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY secret SYSTEM "file:///etc/passwd">]>
<root>&secret;</root>
"""


def test_wds_mdt_parses_ini_credentials():
    module = WDSMDTModule()

    findings = list(module.parse_ini(
        b"[Default]\nUserID=deploy-user\nUserPassword=test-password\nUserDomain=example.test\n",
        "DeploymentShare$\\Control\\Bootstrap.ini",
    ))

    assert findings == [(
        "DeploymentShare$\\Control\\Bootstrap.ini",
        {"UserID": "deploy-user", "UserPassword": "test-password", "UserDomain": "example.test"},
        [("example.test", "deploy-user", "test-password")],
    )]


def test_wds_mdt_rejects_external_xml_entities():
    module = WDSMDTModule()

    with pytest.raises(EntitiesForbidden):
        list(module.parse_xml(MALICIOUS_XML, "DeploymentShare$\\Control\\Unattend.xml"))


def test_mremoteng_rejects_external_xml_entities():
    module = MRemoteNGModule()

    with pytest.raises(EntitiesForbidden):
        module.handle_confCons_file(MALICIOUS_XML)
