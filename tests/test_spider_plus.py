import io
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from impacket.smb3structs import FILE_READ_DATA
from impacket.smbconnection import SessionError
from nxc.modules.spider_plus import NXCModule
from nxc.protocols.smb.spiderplus import SMBSpiderPlus


class RemoteFileFixture:
    def __init__(self, data, path="web.config", share="Documents", read_error=False):
        self.stream = io.BytesIO(data)
        self.read_error = read_error
        self.opened = False
        self.closed = False
        self.requests = []
        self._RemoteFile__share = share
        self._RemoteFile__fileName = path

    def open_file(self):
        self.opened = True

    def read(self, size):
        self.requests.append(size)
        if self.read_error:
            raise OSError("Test read failure")
        return self.stream.read(size)

    def seek(self, offset, whence):
        self.stream.seek(offset, whence)

    def close(self):
        self.closed = True


class TestSpiderPlus:
    @pytest.fixture(autouse=True)
    def setup(self, tmp_path):
        self.output_folder = str(tmp_path)
        self.smb = Mock()
        self.smb.conn.getRemoteHost.return_value = "192.0.2.10"
        self.logger = Mock()
        return self

    def make_spider(self, **options):
        spider = SMBSpiderPlus(self.smb, self.logger, False, True, ["ico", "lnk"], ["print$", "ipc$"], 50 * 1024, self.output_folder, **options)
        spider.results["Documents"] = {}
        return spider

    def file_info(self, size, name="web.config"):
        return SimpleNamespace(
            get_filesize=lambda: size, get_longname=lambda: name, is_directory=lambda: False,
            get_ctime_epoch=lambda: 0, get_mtime_epoch=lambda: 0, get_atime_epoch=lambda: 0,
        )

    def finding(self, spider, path="web.config"):
        return spider.results["Documents"][path]["sensitive"]

    def test_known_names_and_backups(self):
        for path in ("WEB.CONFIG", "backup/web.config.bak", r"Windows\Panther\Unattend.xml", "tomcat-users.xml", "wp-config.php", "SiteList.xml", "FileZilla.xml", "ConsoleHost_history.txt", ".aws/credentials", ".env.production", "id_rsa", "id_ed25519", "vault.kdbx", "cert.pfx", "NTDS.dit", "SAM", "SYSTEM", "ntuser.dat", "key4.db", "Login Data", "appsettings.Production.json", "terraform.tfstate.backup", "passwords.txt", "credentials.xlsx", "secret.key", ".git-credentials"):
            assert SMBSpiderPlus.sensitive_name_matches(path)

    def test_ordinary_names_and_public_keys(self):
        for path in ("readme.txt", "application.config", "drawing.keynote", "compass.txt", "bypass.log", "known_hosts", "id_rsa.pub", "certificate.cer", "request.csr", "server.crt", "report.docx", "logo.png"):
            assert SMBSpiderPlus.sensitive_name_matches(path) == []

    def test_literal_content_indicators(self):
        for data in (
            b'<add connectionString="Server=db;Password=ExampleTest123;User ID=test;" />',
            b'{"client_secret": "example-test-secret"}', b"export API_KEY='example-test-key'",
            b"<Password><Value>example-test-value</Value><PlainText>true</PlainText></Password>",
            b'<add key="password" value="example-test-value" />', b"jdbc:postgresql://test:example-test-value@db/example",
            b"-----BEGIN OPENSSH PRIVATE KEY-----\nTEST\n-----END OPENSSH PRIVATE KEY-----",
            b"PuTTY-User-Key-File-3: ssh-ed25519", b"aws_secret_access_key = example-test-value",
        ):
            assert SMBSpiderPlus.sensitive_content_matches(data)

    def test_content_without_values_is_not_flagged(self):
        for data in (
            b"Documentation about password policies and JDBC/ODBC.", b'password=""', b'password="${DB_PASSWORD}"',
            b'password="%DB_PASSWORD%"', b'password="{{ DB_PASSWORD }}"', b'password="redacted"',
            b"password=process.env.PASSWORD", b'password=os.getenv("PASSWORD")', b'password="***"',
            b"password=$DB_PASSWORD", b"<Password></Password>",
            b"postgresql://test:${DB_PASSWORD}@db/example", b"-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----",
        ):
            assert SMBSpiderPlus.sensitive_content_matches(data) == []

    def test_real_values_are_not_mistaken_for_placeholders(self):
        for data in (b'password="$yntheticTest123"', b'password="%ExampleTest123"', b'password="changeme"', b'password="change_me"', b'password="true"', b'password="null"'):
            assert "credential assignment" in SMBSpiderPlus.sensitive_content_matches(data)

    def test_credentials_in_comments_are_still_reported(self):
        for data in (b'# password="ExampleTest123"', b'// password="ExampleTest123"', b'; password="ExampleTest123"', b'<!-- password="ExampleTest123" -->'):
            assert "credential assignment" in SMBSpiderPlus.sensitive_content_matches(data)

    def test_utf16_and_binary_content(self):
        assert SMBSpiderPlus.sensitive_content_matches('password="example-test-value"'.encode("utf-16"))
        assert SMBSpiderPlus.sensitive_content_matches(b"\x00password=example-test-value") is None

    def test_download_paths_stay_inside_output_folder(self):
        spider = self.make_spider()
        for path in ("../outside/id_rsa", "/outside/id_rsa", r"C:\outside\id_rsa", r"..\outside\id_rsa"):
            folder, name = spider.get_file_save_path(RemoteFileFixture(b"", path, "../Documents"))
            target = Path(folder) / name
            assert target.resolve().is_relative_to(Path(self.output_folder).resolve())
            assert name == "id_rsa"

    def test_ipv6_output_names_are_valid_on_windows(self):
        self.smb.conn.getRemoteHost.return_value = "2001:db8::1"
        spider = self.make_spider()
        folder, name = spider.get_file_save_path(RemoteFileFixture(b""))
        assert Path(folder).parts[-2:] == ("2001_db8__1", "Documents")
        assert name == "web.config"

    @patch("nxc.protocols.smb.spiderplus.RemoteFile")
    def test_default_does_not_read_remote_files(self, remote_file):
        spider = self.make_spider()
        spider.parse_file("Documents", "web.config", self.file_info(100))
        remote_file.assert_not_called()
        assert self.finding(spider)["name_matches"]
        assert self.finding(spider)["content_status"] == "not_requested"
        assert spider.stats["num_sensitive_files"] == 1

    @patch("nxc.protocols.smb.spiderplus.RemoteFile")
    def test_disabled_preserves_metadata_without_checks(self, remote_file):
        spider = self.make_spider(sensitive_check_enable=False, sensitive_check_staticonly=False)
        spider.parse_file("Documents", "web.config", self.file_info(100))
        remote_file.assert_not_called()
        assert "sensitive" not in spider.results["Documents"]["web.config"]

    @patch("nxc.protocols.smb.spiderplus.RemoteFile")
    def test_remote_content_mode_reads_without_downloading(self, remote_file):
        data = b'<add connectionString="Password=example-test-value;" />'
        remote = RemoteFileFixture(data)
        remote_file.return_value = remote
        spider = self.make_spider(sensitive_check_staticonly=False)
        spider.parse_file("Documents", "web.config", self.file_info(len(data)))
        remote_file.assert_called_once_with(self.smb.conn, "web.config", "Documents", access=FILE_READ_DATA)
        assert remote.closed
        assert self.finding(spider)["content_status"] == "checked"
        assert self.finding(spider)["content_matches"]
        assert self.finding(spider)["content_source"] == "remote"
        assert list(Path(self.output_folder).rglob("*")) == []

    @patch("nxc.protocols.smb.spiderplus.RemoteFile")
    def test_benign_config_retains_only_filename_hint(self, remote_file):
        data = b"<configuration><appSettings /></configuration>"
        remote_file.return_value = RemoteFileFixture(data)
        spider = self.make_spider(sensitive_check_staticonly=False)
        spider.parse_file("Documents", "web.config", self.file_info(len(data)))
        assert self.finding(spider)["name_matches"]
        assert self.finding(spider)["content_matches"] == []
        assert self.finding(spider)["content_status"] == "checked"

    @patch("nxc.protocols.smb.spiderplus.RemoteFile")
    def test_content_mode_finds_unflagged_text_filename(self, remote_file):
        data = b"password=example-test-value"
        remote_file.return_value = RemoteFileFixture(data)
        spider = self.make_spider(sensitive_check_staticonly=False)
        spider.parse_file("Documents", "notes.txt", self.file_info(len(data)))
        assert not self.finding(spider, "notes.txt")["name_matches"]
        assert self.finding(spider, "notes.txt")["content_matches"]
        assert spider.stats["num_sensitive_files"] == 1

    @patch("nxc.protocols.smb.spiderplus.RemoteFile")
    def test_download_is_checked_automatically_without_second_remote_read(self, remote_file):
        data = b"password=example-test-value"
        remote = RemoteFileFixture(data, "notes.txt")
        remote_file.return_value = remote
        spider = self.make_spider()
        spider.download_flag = True
        spider.parse_file("Documents", "notes.txt", self.file_info(len(data)))
        remote_file.assert_called_once()
        assert self.finding(spider, "notes.txt")["content_source"] == "download"
        assert self.finding(spider, "notes.txt")["content_matches"]
        assert remote.closed
        assert spider.stats["num_get_success"] == 1
        assert (Path(self.output_folder) / "192.0.2.10/Documents/notes.txt").read_bytes() == data

    @patch("nxc.protocols.smb.spiderplus.RemoteFile")
    def test_cached_download_is_rechecked_without_remote_open(self, remote_file):
        data = b"password=example-test-value"
        remote = RemoteFileFixture(data)
        remote_file.return_value = remote
        target = Path(self.output_folder) / "192.0.2.10/Documents/web.config"
        target.parent.mkdir(parents=True)
        target.write_bytes(data)
        spider = self.make_spider()
        spider.download_flag = True
        spider.parse_file("Documents", "web.config", self.file_info(len(data)))
        assert not remote.opened
        assert self.finding(spider)["content_matches"]
        assert spider.stats["num_files_unmodified"] == 1

    @patch("nxc.protocols.smb.spiderplus.RemoteFile")
    def test_size_limit_prevents_remote_reads(self, remote_file):
        spider = self.make_spider(sensitive_check_staticonly=False, sensitive_check_max_file_size=16)
        spider.parse_file("Documents", "web.config", self.file_info(17))
        remote_file.assert_not_called()
        assert self.finding(spider)["content_status"] == "skipped_size"

    @patch("nxc.protocols.smb.spiderplus.RemoteFile")
    def test_content_limit_also_applies_to_downloads(self, remote_file):
        data = b"password=example-test-value"
        remote_file.return_value = RemoteFileFixture(data)
        spider = self.make_spider(sensitive_check_max_file_size=16)
        spider.download_flag = True
        spider.parse_file("Documents", "web.config", self.file_info(len(data)))
        assert self.finding(spider)["content_status"] == "skipped_size"
        assert spider.stats["num_get_success"] == 1

    @patch("nxc.protocols.smb.spiderplus.RemoteFile")
    def test_server_cannot_exceed_content_read_limit(self, remote_file):
        remote = RemoteFileFixture(b"x" * 100)
        remote_file.return_value = remote
        spider = self.make_spider(sensitive_check_staticonly=False, sensitive_check_max_file_size=16)
        spider.parse_file("Documents", "web.config", self.file_info(10))
        assert self.finding(spider)["content_status"] == "skipped_size"
        assert sum(remote.requests) == 17
        assert remote.closed

    @patch("nxc.protocols.smb.spiderplus.RemoteFile")
    def test_binary_store_is_flagged_without_remote_content_read(self, remote_file):
        spider = self.make_spider(sensitive_check_staticonly=False)
        spider.parse_file("Documents", "vault.kdbx", self.file_info(10))
        remote_file.assert_not_called()
        assert self.finding(spider, "vault.kdbx")["name_matches"]
        assert self.finding(spider, "vault.kdbx")["content_status"] == "skipped_type"

    @patch("nxc.protocols.smb.spiderplus.RemoteFile")
    def test_documents_and_archives_are_not_read_as_text(self, remote_file):
        spider = self.make_spider(sensitive_check_staticonly=False)
        for path in ("credentials.xlsx", "passwords.zip"):
            spider.parse_file("Documents", path, self.file_info(10))
            assert self.finding(spider, path)["name_matches"]
            assert self.finding(spider, path)["content_status"] == "skipped_type"
        remote_file.assert_not_called()

    @patch("nxc.protocols.smb.spiderplus.RemoteFile")
    def test_disabled_checks_do_not_inspect_downloads(self, remote_file):
        data = b"password=example-test-value"
        remote_file.return_value = RemoteFileFixture(data)
        spider = self.make_spider(sensitive_check_enable=False)
        spider.download_flag = True
        with patch.object(spider, "check_sensitive_content") as check_content:
            spider.parse_file("Documents", "web.config", self.file_info(len(data)))
            check_content.assert_not_called()
        assert "sensitive" not in spider.results["Documents"]["web.config"]
        assert spider.stats["num_get_success"] == 1

    @patch("nxc.protocols.smb.spiderplus.RemoteFile")
    def test_excluded_extension_prevents_content_read(self, remote_file):
        spider = self.make_spider(sensitive_check_staticonly=False)
        spider.exclude_exts = [".config"]
        spider.parse_file("Documents", "web.config", self.file_info(10))
        remote_file.assert_not_called()
        assert self.finding(spider)["content_status"] == "excluded"

    @patch("nxc.protocols.smb.spiderplus.RemoteFile")
    def test_read_failures_are_not_reported_as_checked(self, remote_file):
        remote = RemoteFileFixture(b"", read_error=True)
        remote_file.return_value = remote
        spider = self.make_spider(sensitive_check_staticonly=False)
        spider.parse_file("Documents", "web.config", self.file_info(10))
        assert self.finding(spider)["content_status"] == "read_error"
        assert self.finding(spider)["content_matches"] == []
        assert remote.closed
        self.logger.fail.assert_called()

    @patch("nxc.protocols.smb.spiderplus.RemoteFile", side_effect=OSError("Test open failure"))
    def test_open_failures_are_recorded(self, remote_file):
        spider = self.make_spider(sensitive_check_staticonly=False)
        spider.parse_file("Documents", "web.config", self.file_info(10))
        assert self.finding(spider)["content_status"] == "read_error"

    @patch("nxc.protocols.smb.spiderplus.RemoteFile")
    def test_truncated_reads_do_not_confirm_content(self, remote_file):
        data = b"password=example-test-value"
        remote_file.return_value = RemoteFileFixture(data)
        spider = self.make_spider(sensitive_check_staticonly=False)
        spider.parse_file("Documents", "web.config", self.file_info(len(data) + 1))
        assert self.finding(spider)["content_status"] == "size_changed"
        assert self.finding(spider)["content_matches"] == []

    @patch("nxc.protocols.smb.spiderplus.RemoteFile")
    def test_cross_chunk_content_matches(self, remote_file):
        data = b" " * 4092 + b"password=example-test-value"
        remote_file.return_value = RemoteFileFixture(data)
        spider = self.make_spider(sensitive_check_staticonly=False)
        spider.parse_file("Documents", "web.config", self.file_info(len(data)))
        assert self.finding(spider)["content_matches"]

    @patch("nxc.protocols.smb.spiderplus.RemoteFile")
    def test_failed_download_is_not_scanned_or_counted_as_success(self, remote_file):
        remote = RemoteFileFixture(b"", read_error=True)
        remote_file.return_value = remote
        spider = self.make_spider()
        spider.download_flag = True
        spider.parse_file("Documents", "web.config", self.file_info(10))
        assert self.finding(spider)["content_status"] == "download_failed"
        assert spider.stats["num_get_success"] == 0
        assert spider.stats["num_get_fail"] == 1
        assert remote.closed
        assert not (Path(self.output_folder) / "192.0.2.10/Documents/web.config").exists()

    @patch("nxc.protocols.smb.spiderplus.RemoteFile")
    def test_download_permission_denial_is_logged(self, remote_file):
        remote = RemoteFileFixture(b"")
        remote.open_file = Mock(side_effect=SessionError(error=0xC0000022))
        remote_file.return_value = remote
        spider = self.make_spider()
        spider.download_flag = True
        spider.parse_file("Documents", "web.config", self.file_info(10))
        assert self.finding(spider)["content_status"] == "download_failed"
        assert remote.closed
        self.logger.fail.assert_called()

    @patch("nxc.protocols.smb.spiderplus.RemoteFile")
    def test_download_size_mismatch_removes_partial_output(self, remote_file):
        for expected_size in (1, 100):
            remote_file.return_value = RemoteFileFixture(b"test")
            spider = self.make_spider()
            spider.download_flag = True
            spider.parse_file("Documents", "web.config", self.file_info(expected_size))
            assert self.finding(spider)["content_status"] == "download_failed"
            assert not (Path(self.output_folder) / "192.0.2.10/Documents/web.config").exists()

    @patch("nxc.protocols.smb.spiderplus.RemoteFile")
    def test_download_filter_does_not_limit_opt_in_content_mode(self, remote_file):
        data = b"password=example-test-value"
        remote_file.return_value = RemoteFileFixture(data)
        spider = self.make_spider(sensitive_check_staticonly=False)
        spider.download_flag = True
        spider.max_file_size = 1
        spider.parse_file("Documents", "web.config", self.file_info(len(data)))
        assert self.finding(spider)["content_source"] == "remote"
        assert self.finding(spider)["content_matches"]
        assert spider.stats["num_get_success"] == 0

    @patch("nxc.protocols.smb.spiderplus.RemoteFile")
    def test_spider_only_visits_readable_and_nonexcluded_shares(self, remote_file):
        self.smb.shares.return_value = [
            {"name": "Documents", "access": ["READ"]},
            {"name": "NoAccess", "access": []},
            {"name": "print$", "access": ["READ"]},
        ]
        self.smb.conn.listPath.return_value = [self.file_info(10)]
        spider = self.make_spider()
        spider.spider_shares()
        self.smb.conn.listPath.assert_called_once_with("Documents", "*")
        remote_file.assert_not_called()
        metadata = json.loads((Path(self.output_folder) / "192.0.2.10.json").read_text())
        assert set(metadata) == {"Documents"}
        assert metadata["Documents"]["web.config"]["sensitive"]["name_matches"]

    def test_module_option_defaults_and_false_values(self):
        module = NXCModule()
        context = SimpleNamespace(log=self.logger)
        module.options(context, {"OUTPUT_FOLDER": self.output_folder})
        assert not module.download_flag
        assert module.stats_flag
        assert module.sensitive_check_enable
        assert module.sensitive_check_staticonly
        assert module.sensitive_check_max_file_size == 1024 * 1024
        module.options(context, {"OUTPUT_FOLDER": self.output_folder, "DOWNLOAD_FLAG": "False", "STATS_FLAG": "False", "SENSITIVE_CHECK_ENABLE": "false", "SENSITIVE_CHECK_STATICONLY": "False"})
        assert not module.download_flag
        assert not module.stats_flag
        assert not module.sensitive_check_enable
        assert not module.sensitive_check_staticonly

    def test_invalid_sensitive_options_fail_with_explanation(self):
        for options in ({"SENSITIVE_CHECK_ENABLE": "typo"}, {"SENSITIVE_CHECK_STATICONLY": "typo"}, {"SENSITIVE_CHECK_MAX_FILE_SIZE": "0"}, {"SENSITIVE_CHECK_MAX_FILE_SIZE": "-1"}, {"SENSITIVE_CHECK_MAX_FILE_SIZE": "typo"}):
            with pytest.raises(SystemExit):
                NXCModule().options(SimpleNamespace(log=self.logger), options)
        self.logger.fail.assert_called()

    @patch("nxc.modules.spider_plus.SMBSpiderPlus")
    def test_module_passes_sensitive_options_to_spider(self, spider_class):
        module = NXCModule()
        context = SimpleNamespace(log=self.logger)
        module.options(context, {"OUTPUT_FOLDER": self.output_folder, "SENSITIVE_CHECK_STATICONLY": "False", "SENSITIVE_CHECK_MAX_FILE_SIZE": "2048"})
        module.on_login(context, self.smb)
        assert spider_class.call_args.kwargs == {"sensitive_check_enable": True, "sensitive_check_staticonly": False, "sensitive_check_max_file_size": 2048}
        spider_class.return_value.spider_shares.assert_called_once()
