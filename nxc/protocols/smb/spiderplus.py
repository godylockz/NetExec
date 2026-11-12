#!/usr/bin/env python3
# -- coding: utf-8 --

# Imports
import json
import errno
import logging
from os.path import join, exists, splitext, getsize
from os import makedirs, remove, stat
from pathlib import Path, PurePosixPath
import time
import re
from fnmatch import fnmatchcase
from contextlib import suppress
from nxc.helpers.path import sanitize_path_component
from nxc.helpers.smb import get_last_write_time
from nxc.protocols.smb.remotefile import RemoteFile
from impacket.smb3structs import FILE_READ_DATA
from impacket.smbconnection import SessionError
from impacket.nmb import NetBIOSTimeout

try:
    from kreuzberg import ExtractionConfig, OcrConfig, extract_bytes_sync
except ImportError as e:
    extract_bytes_sync = None
    logging.getLogger(__name__).debug("Document extraction unavailable: %s", e)


CHUNK_SIZE = 4096


def human_size(nbytes):
    """Takes a number of bytes as input and converts it to a human-readable size representation with appropriate units (e.g., KB, MB, GB, TB)"""
    suffixes = ["B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"]

    # Find the appropriate unit suffix and convert bytes to higher units
    for i in range(len(suffixes)):
        if nbytes < 1024 or i == len(suffixes) - 1:
            break
        nbytes /= 1024.0

    # Format the number of bytes with two decimal places and remove trailing zeros and decimal point
    size_str = f"{nbytes:.2f}".rstrip("0").rstrip(".")

    # Return the human-readable size with the appropriate unit suffix
    return f"{size_str} {suffixes[i]}"


def human_time(timestamp):
    """Takes a numerical timestamp (seconds since the epoch) and formats it as a human-readable date and time in the format "YYYY-MM-DD HH:MM:SS"""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))


def make_dirs(path):
    """Creates directories at the given path. It handles the exception `os.errno.EEXIST` that may occur if the directories already exist."""
    try:
        makedirs(path)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise


def get_list_from_option(opt):
    """Takes a comma-separated string and converts it to a list of lowercase strings.
    It filters out empty strings from the input before converting.
    """
    return [o.lower() for o in filter(bool, opt.split(","))]


class SMBSpiderPlus:
    document_types = {
        ".pdf": "application/pdf",
        ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        ".odt": "application/vnd.oasis.opendocument.text",
        ".ods": "application/vnd.oasis.opendocument.spreadsheet",
        ".rtf": "application/rtf",
        ".doc": "application/msword",
        ".xls": "application/vnd.ms-excel",
        ".ppt": "application/vnd.ms-powerpoint",
    }
    image_types = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".tif": "image/tiff", ".tiff": "image/tiff", ".bmp": "image/bmp", ".webp": "image/webp"}
    sensitive_name_rules = {
        "credential configuration": (
            "web.config", "applicationhost.config", "wp-config.php", "config.php", "settings.php",
            "tomcat-users.xml", "unattend.xml", "unattended.xml", "unattend.txt", "unattend.inf",
            "sysprep.xml", "sysprep.inf", "anaconda-ks.cfg", "sitelist.xml", "vnc.ini", "ultravnc.ini",
            "freesshdservice.ini", "rsyncd.conf", "hostapd.conf", "cesi.conf", "supervisord.conf",
            "my.ini", "my.cnf", "database.yml", ".env", ".env.*", "appsettings*.json", "*.tfstate",
        ),
        "credential store": (
            "filezilla.xml", "sitemanager.xml", "recentservers.xml", "winscp.ini", "rdcman.settings",
            "*.rdg", "*.ovpn", ".htpasswd", ".git-credentials", ".netrc", "_netrc", "credentials.xml", ".npmrc", ".pypirc",
            "access_tokens.db", "accesstokens.json", "credentials.db", "application_default_credentials.json",
            "ntds.dit", "sam", "system", "security", "ntuser.dat", "key3.db", "key4.db", "logins.json",
            "login data", "signons.sqlite", "cwallet.sso",
        ),
        "private key or key container": (
            "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ecdsa_sk", "id_ed25519_sk",
            "id_*.pem", "private*.pem", "*.key", "*.ppk", "*.pfx", "*.p12", "*.jks", "*.keystore",
        ),
        "password vault": ("*.kdb", "*.kdbx", "*.psafe3"),
        "command history": ("consolehost_history.txt", ".bash_history", ".zsh_history", ".mysql_history", ".psql_history"),
    }
    text_extensions = {
        ".config", ".conf", ".cfg", ".ini", ".xml", ".json", ".yml", ".yaml", ".env", ".properties", ".toml",
        ".txt", ".log", ".ps1", ".bat", ".cmd", ".sh", ".py", ".php", ".cs", ".vb", ".sql", ".tf", ".tfvars",
        ".tfstate", ".rdp", ".rdg", ".pem", ".key", ".ppk", ".ovpn", ".csv", ".tsv", ".md", ".rst", ".html", ".htm",
    }
    binary_extensions = {
        ".kdb", ".kdbx", ".psafe3", ".pfx", ".p12", ".jks", ".keystore", ".db", ".sqlite", ".dit", ".dat", ".sso",
        ".zip", ".7z", ".rar", ".gz", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".odp", ".exe", ".dll",
    }
    credential_key = r"(?:password|passwd|pwd|db[_-]?password|api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|aws[_-]?secret[_-]?access[_-]?key|aws[_-]?access[_-]?key[_-]?id|secret|token)"
    assignment_pattern = re.compile(
        rf"""(?<![\w])['"]?{credential_key}['"]?[ \t]{{0,16}}[:=][ \t]{{0,16}}(?P<value>"[^"\r\n]{{1,512}}"|'[^'\r\n]{{1,512}}'|[^\s<>&;,'"}}]{{1,512}})""",
        re.IGNORECASE,
    )
    xml_pattern = re.compile(rf"<{credential_key}\b[^>]{{0,512}}>\s*(?:<Value>\s*)?(?P<value>[^<\r\n]{{1,512}})", re.IGNORECASE)
    private_key_pattern = re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----|PuTTY-User-Key-File-[23]:")
    uri_pattern = re.compile(r"\b[a-z][a-z0-9+.-]{1,20}://[^\s/:@]{1,128}:(?P<value>[^\s/@]{1,256})@", re.IGNORECASE)

    def __init__(
        self,
        smb,
        logger,
        download_flag,
        stats_flag,
        exclude_exts,
        exclude_filter,
        max_file_size,
        output_folder,
        sensitive_check=True,
        sensitive_read_content=False,
        sensitive_max_file_size=1024 * 1024,
        documents=False,
        ocr=False,
        name_regex=None,
        content_patterns=(),
        shares=(),
        include_exts=(),
        include_dirs=(),
        exclude_dirs=(),
        depth=None,
        modified_after=None,
        modified_before=None,
    ):
        self.smb = smb
        self.host = self.smb.conn.getRemoteHost()
        self.output_host = sanitize_path_component(self.host)
        self.max_connection_attempts = 5
        self.logger = logger
        self.results = {}
        self.stats = {
            "shares": [],
            "shares_readable": [],
            "shares_writable": [],
            "num_shares_filtered": 0,
            "num_folders": 0,
            "num_folders_filtered": 0,
            "num_files": 0,
            "file_sizes": [],
            "file_exts": set(),
            "num_get_success": 0,
            "num_get_fail": 0,
            "num_files_filtered": 0,
            "num_files_unmodified": 0,
            "num_files_updated": 0,
            "num_sensitive_files": 0,
            "num_sensitive_content_matches": 0,
        }
        self.download_flag = download_flag
        self.stats_flag = stats_flag
        self.exclude_filter = exclude_filter
        self.exclude_exts = exclude_exts
        self.max_file_size = max_file_size
        self.output_folder = output_folder
        self.sensitive_check = sensitive_check
        self.sensitive_read_content = sensitive_read_content
        self.sensitive_max_file_size = sensitive_max_file_size
        self.documents = documents
        self.ocr = ocr
        self.name_regex = name_regex
        self.content_patterns = content_patterns
        self.shares = shares
        self.include_exts = include_exts
        self.include_dirs = include_dirs
        self.exclude_dirs = exclude_dirs
        self.depth = depth
        self.modified_after = modified_after
        self.modified_before = modified_before
        self.read_content = bool(content_patterns) or (sensitive_check and (sensitive_read_content or documents))

        # Make sure the output_folder exists
        make_dirs(self.output_folder)

    @staticmethod
    def sensitive_name_matches(file_path):
        path = file_path.replace("\\", "/").lower()
        name = path.rsplit("/", 1)[-1]
        name = re.sub(r"(?:\.(?:bak|backup|old|orig|save))+~?$|~$", "", name)
        if name.endswith((".pub", ".cer", ".crt", ".csr")):
            return []
        matches = [reason for reason, patterns in SMBSpiderPlus.sensitive_name_rules.items() if any(fnmatchcase(name, pattern) for pattern in patterns)]
        if re.search(r"(?:^|[._ -])(?:passwords?|passwd|credentials?|secrets?)(?:[._ -]|$)", name):
            matches.append("credential-like filename")
        if path.endswith(".aws/credentials") or "/gcloud/legacy_credentials/" in f"/{path}":
            matches.append("cloud credential path")
        return matches

    @staticmethod
    def has_literal_value(value):
        value = value.strip()
        quoted = len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]
        if not quoted and value.lower() in {"null", "none", "true", "false"}:
            return False
        value = value.strip("\"'")
        if not value or value.lower() in {"redacted", "your_password", "replace_me"}:
            return False
        if re.fullmatch(r"\$\{[^}]+\}|\$\([^)]+\)|%[^%]+%|\{\{[^}]+\}\}|<[^>]+>", value):
            return False
        if not quoted and re.fullmatch(r"\$[A-Za-z_]\w*", value):
            return False
        if value.startswith(("process.env.", "process.env[", "os.environ[", "os.environ.get(", "os.getenv(", "getenv(", "env(")):
            return False
        return not re.fullmatch(r"\*+|[xX]{3,}", value)

    @staticmethod
    def document_parser_available():
        return extract_bytes_sync is not None

    @staticmethod
    def decode_content(data):
        if data.startswith((b"\xff\xfe", b"\xfe\xff")):
            text = data.decode("utf-16", errors="replace")
        elif b"\x00" in data:
            return None
        else:
            text = data.decode("utf-8-sig", errors="replace")
        if any(ord(char) < 32 and char not in "\r\n\t" for char in text):
            return None
        return text

    @staticmethod
    def sensitive_content_matches(data):
        text = SMBSpiderPlus.decode_content(data)
        return SMBSpiderPlus.sensitive_text_matches(text) if text is not None else None

    @staticmethod
    def sensitive_text_matches(text):
        matches = []
        if SMBSpiderPlus.private_key_pattern.search(text):
            matches.append("private key content")
        if any(SMBSpiderPlus.has_literal_value(match["value"]) for match in SMBSpiderPlus.uri_pattern.finditer(text)):
            matches.append("credentials in connection URI")
        if any(SMBSpiderPlus.has_literal_value(match["value"]) for match in SMBSpiderPlus.assignment_pattern.finditer(text)):
            matches.append("credential assignment")
        if any(SMBSpiderPlus.has_literal_value(match["value"]) for match in SMBSpiderPlus.xml_pattern.finditer(text)):
            matches.append("credential XML element")
        for tag in re.findall(r"<add\b[^>\n]{0,1024}>", text, re.IGNORECASE):
            key = re.search(r"\b(?:key|name)\s*=\s*['\"]([^'\"]+)['\"]", tag, re.IGNORECASE)
            value = re.search(r"\bvalue\s*=\s*['\"]([^'\"]+)['\"]", tag, re.IGNORECASE)
            if key and value and re.fullmatch(SMBSpiderPlus.credential_key, key[1], re.IGNORECASE) and SMBSpiderPlus.has_literal_value(value[1]):
                matches.append("credential configuration value")
                break
        return matches

    @staticmethod
    def content_status(metadata, status, **details):
        for key in ("sensitive", "search"):
            if key in metadata:
                metadata[key].update(content_status=status, **details)

    def check_sensitive_content(self, share_name, file_path, file_size, download_path=None):
        metadata = self.results[share_name][file_path]
        self.content_status(metadata, "not_requested", content_source="download" if download_path else "remote")
        if file_size > self.sensitive_max_file_size:
            self.content_status(metadata, "skipped_size")
            return
        extension = splitext(file_path)[1].lower()
        mime_type = self.document_types.get(extension) or (self.image_types.get(extension) if self.ocr else None)
        if not (self.documents and mime_type) and (extension in self.binary_extensions or extension in self.document_types or extension in self.image_types or (not download_path and not metadata.get("sensitive", {}).get("name_matches") and extension not in self.text_extensions and not self.content_patterns)):
            self.content_status(metadata, "skipped_type")
            return
        remote_file = None
        try:
            if download_path:
                with open(download_path, "rb") as fd:
                    data = fd.read(self.sensitive_max_file_size + 1)
            else:
                remote_file = RemoteFile(self.smb.conn, file_path, share_name, access=FILE_READ_DATA)
                remote_file.open_file()
                data = bytearray()
                while len(data) <= self.sensitive_max_file_size:
                    chunk = self.read_chunk(remote_file, min(CHUNK_SIZE, self.sensitive_max_file_size + 1 - len(data)))
                    if not chunk:
                        break
                    data.extend(chunk)
            self.content_status(metadata, "not_requested", bytes_checked=len(data))
            if len(data) > self.sensitive_max_file_size:
                self.content_status(metadata, "skipped_size")
                return
            if len(data) != file_size:
                self.content_status(metadata, "size_changed")
                return
            if self.documents and mime_type:
                try:
                    text = extract_bytes_sync(bytes(data), mime_type, config=ExtractionConfig(use_cache=False, disable_ocr=not self.ocr, ocr=OcrConfig(backend="tesseract") if self.ocr else None, extraction_timeout_secs=30)).content
                except Exception as e:
                    self.content_status(metadata, "extraction_error")
                    self.logger.fail(f"Cannot extract document //{self.host}/{share_name}/{file_path}: {e}")
                    return
                if len(text.encode("utf-8")) > self.sensitive_max_file_size:
                    self.content_status(metadata, "skipped_extracted_size")
                    return
                if not text.strip():
                    self.content_status(metadata, "no_text")
                    return
            else:
                text = self.decode_content(data)
            if text is None:
                self.content_status(metadata, "skipped_binary")
                return
            self.content_status(metadata, "checked")
            matches = self.sensitive_text_matches(text) if self.sensitive_check else []
            if self.sensitive_check:
                metadata["sensitive"]["content_matches"] = matches
            if matches:
                self.stats["num_sensitive_content_matches"] += 1
                if not metadata["sensitive"]["name_matches"]:
                    self.stats["num_sensitive_files"] += 1
                self.logger.highlight(f"Sensitive content indicator: //{self.host}/{share_name}/{file_path} ({', '.join(matches)})")
            if self.content_patterns:
                for pattern in self.content_patterns:
                    count = sum(1 for match in pattern.finditer(text))
                    if count:
                        metadata["search"]["content_matches"].append({"pattern": pattern.pattern, "count": count})
                        self.logger.highlight(f"Content search match: //{self.host}/{share_name}/{file_path} ({pattern.pattern}: {count})")
        except Exception as e:
            self.content_status(metadata, "read_error")
            self.logger.fail(f"Cannot check sensitive content in //{self.host}/{share_name}/{file_path}: {e}")
        finally:
            if remote_file:
                try:
                    remote_file.close()
                except Exception as e:
                    self.logger.debug(f"Failed closing sensitive-check file {file_path}: {e}")

    def reconnect(self):
        """Performs a series of reconnection attempts, up to `self.max_connection_attempts`, with a 3-second delay between each attempt.
        It renegotiates the session by creating a new connection object and logging in again.
        """
        for i in range(1, self.max_connection_attempts + 1):
            self.logger.display(f"Reconnection attempt #{i}/{self.max_connection_attempts} to server.")

            # Renegotiate the session
            time.sleep(3)
            self.smb.create_conn_obj()
            self.smb.login()
            return True

        return False

    def list_path(self, share, subfolder):
        """Returns a list of paths for a given share/folder."""
        filelist = []
        try:
            # Get file list for the current folder
            filelist = self.smb.conn.listPath(share, subfolder + "*")

        except SessionError as e:
            self.logger.debug(f'Failed listing files on share "{share}" in folder "{subfolder}": {e!s}')

            if "STATUS_ACCESS_DENIED" in str(e):
                self.logger.debug(f'Cannot list files in folder "{subfolder}".')
            elif "STATUS_OBJECT_PATH_NOT_FOUND" in str(e):
                self.logger.debug(f"The folder {subfolder} does not exist.")
            elif "STATUS_STOPPED_ON_SYMLINK" in str(e):
                self.logger.debug(f"The folder {subfolder} is a symlink that cannot be followed. Skipping.")
            elif "STATUS_NO_SUCH_FILE" in str(e):
                self.logger.debug(f"The folder {subfolder} is empty.")
            elif self.reconnect():
                filelist = self.list_path(share, subfolder)
        except NetBIOSTimeout as e:
            self.logger.debug(f'Failed listing files on share "{share}" in folder "{subfolder}": {e!s}')
        return filelist

    def get_remote_file(self, share, path):
        """Checks if a path is readable in a SMB share."""
        try:
            return RemoteFile(self.smb.conn, path, share, access=FILE_READ_DATA)
        except SessionError as e:
            self.logger.debug(f"Cannot access {share}/{path}: {e}")
            return None

    def read_chunk(self, remote_file, chunk_size=CHUNK_SIZE):
        """Return EOF only for a completed read; propagate failures to the caller."""
        try:
            return remote_file.read(chunk_size)
        except SessionError as e:
            if "STATUS_END_OF_FILE" in str(e):
                return b""
            raise

    def get_file_save_path(self, remote_file):
        r"""Processes the remote file path to extract the filename and the folder path where the file should be saved locally.

        Strip remote path anchors and traversal components, sanitize each local
        path component, and verify containment in the output folder.
        """
        self.logger.debug(f"Remote file: {remote_file}")
        clean_parts = []
        for part in (remote_file._RemoteFile__share, remote_file._RemoteFile__fileName):
            raw_path = PurePosixPath(part.replace("\\", "/"))
            clean_parts.extend(sanitize_path_component(p) for p in raw_path.parts if p not in ("..", ".", raw_path.anchor))
        resolved = Path(self.output_folder).joinpath(self.output_host, *clean_parts)
        if not resolved.resolve().is_relative_to(Path(self.output_folder).resolve()):
            raise ValueError("Remote file path escapes OUTPUT_FOLDER")
        self.logger.debug(f"Resolved path: {resolved}")
        return str(resolved.parent), resolved.name

    def spider_shares(self):
        """Enumerates all available shares for the SMB connection, spiders through the readable shares, and saves the metadata of the shares to a JSON file"""
        self.logger.info("Enumerating shares for spidering.")
        shares = self.smb.shares()

        try:
            # Get all available shares for the SMB connection
            for share in shares:
                share_perms = share["access"]
                share_name = share["name"]
                self.stats["shares"].append(share_name)

                self.logger.info(f'Share "{share_name}" has perms {share_perms}')
                if "WRITE" in share_perms:
                    self.stats["shares_writable"].append(share_name)
                if "READ" in share_perms:
                    self.stats["shares_readable"].append(share_name)
                else:
                    # We only want to spider readable shares
                    self.logger.debug(f'Share "{share_name}" not readable.')
                    continue

                # `exclude_filter` is applied to the shares name
                if share_name.lower() in self.exclude_filter or (self.shares and share_name.lower() not in self.shares):
                    self.logger.info(f'Share "{share_name}" has been excluded.')
                    self.stats["num_shares_filtered"] += 1
                    continue

                try:
                    # Start the spider at the root of the share folder
                    self.results[share_name] = {}
                    self.spider_folder(share_name, "")
                except (SessionError, NetBIOSTimeout) as e:
                    self.logger.exception(e)
                    self.logger.fail(f"Got a session or NetBIOSTimeout error while spidering share: {share_name}")
                    self.reconnect()

        except Exception as e:
            self.logger.exception(e)
            self.logger.fail(f"Error enumerating shares: {e!s}")

        # Save the metadata.
        self.dump_folder_metadata(self.results)

        # Print stats.
        if self.stats_flag:
            self.print_stats()

        return self.results

    def spider_folder(self, share_name, folder, depth=0):
        """Traverses through the contents of the specified share and folder.

        It checks each entry (file or folder) against various filters, performs file metadata recording, and downloads eligible files if the download flag is set.
        """
        self.logger.info(f'Spider share "{share_name}" in folder "{folder}".')

        filelist = self.list_path(share_name, folder)

        # For each entry:
        # - It's a folder then we spider it (skipping `.` and `..`)
        # - It's a file then we apply the checks
        for result in filelist:
            next_filedir = result.get_longname()
            if next_filedir in [".", ".."]:
                continue
            next_fullpath = folder + next_filedir
            result_type = "folder" if result.is_directory() else "file"
            self.stats[f"num_{result_type}s"] += 1

            # Check file-dir exclusion filter.
            if any(d in next_filedir.lower() for d in self.exclude_filter):
                self.logger.info(f'The {result_type} "{next_filedir}" has been excluded')
                self.stats[f"num_{result_type}s_filtered"] += 1
                continue

            if result_type == "folder":
                if (self.depth is not None and depth >= self.depth) or any(part.replace("\\", "/") in next_fullpath.lower() for part in self.exclude_dirs):
                    self.stats["num_folders_filtered"] += 1
                    continue
                self.logger.info(f'Current folder in share "{share_name}": "{next_fullpath}"')
                self.spider_folder(share_name, next_fullpath + "/", depth + 1)
            else:
                self.logger.info(f'Current file in share "{share_name}": "{next_fullpath}"')
                self.parse_file(share_name, next_fullpath, result)

    def parse_file(self, share_name, file_path, file_info):
        """Checks file attributes against various filters, records file metadata, and downloads eligible files if the download flag is set"""
        # Record the file metadata
        file_size = file_info.get_filesize()
        file_creation_time = file_info.get_ctime_epoch()
        file_modified_time = get_last_write_time(file_info)
        file_access_time = file_info.get_atime_epoch()
        self.results[share_name][file_path] = {
            "size": human_size(file_size),
            "ctime_epoch": human_time(file_creation_time),
            "mtime_epoch": human_time(file_modified_time),
            "atime_epoch": human_time(file_access_time),
        }
        self.stats["file_sizes"].append(file_size)

        metadata = self.results[share_name][file_path]
        if self.name_regex or self.content_patterns:
            metadata["search"] = {
                "name_match": bool(self.name_regex and self.name_regex.search(file_path.rsplit("/", 1)[-1])),
                "content_matches": [], "content_status": "not_requested", "bytes_checked": 0,
            }
        extension = splitext(file_path)[1].lower().lstrip(".") or "<none>"
        folder = file_path.rpartition("/")[0].lower()
        for reason, excluded in (
            ("filename", self.name_regex and not metadata["search"]["name_match"]),
            ("extension", self.include_exts and extension not in self.include_exts),
            ("directory", self.include_dirs and not any(part.replace("\\", "/") in folder for part in self.include_dirs)),
            ("modified_after", self.modified_after is not None and file_modified_time < self.modified_after),
            ("modified_before", self.modified_before is not None and file_modified_time >= self.modified_before),
        ):
            if excluded:
                metadata["filter_status"] = reason
                self.content_status(metadata, "excluded")
                self.stats["num_files_filtered"] += 1
                return
        if self.name_regex:
            self.logger.highlight(f"Filename search match: //{self.host}/{share_name}/{file_path}")

        if self.sensitive_check:
            name_matches = self.sensitive_name_matches(file_path)
            self.results[share_name][file_path]["sensitive"] = {
                "name_matches": name_matches,
                "content_matches": [],
                "content_status": "not_requested",
                "bytes_checked": 0,
            }
            if name_matches:
                self.stats["num_sensitive_files"] += 1
                self.logger.highlight(f"Potentially sensitive filename: //{self.host}/{share_name}/{file_path} ({', '.join(name_matches)})")

        if not self.download_flag and not self.read_content:
            return

        # Check file extension filter.
        _, file_extension = splitext(file_path)
        if file_extension:
            file_extension = file_extension.lstrip(".")
            self.stats["file_exts"].add(file_extension.lower())
            if file_extension.lower() in [ext.lstrip(".") for ext in self.exclude_exts]:
                self.logger.info(f'The file "{file_path}" has an excluded extension.')
                self.stats["num_files_filtered"] += 1
                self.content_status(metadata, "excluded")
                return

        if not self.download_flag:
            self.check_sensitive_content(share_name, file_path, file_size)
            return

        self.content_status(metadata, "not_downloaded")

        # Check file size limits.
        if file_size > self.max_file_size:
            self.logger.info(f"File {file_path} has size {human_size(file_size)} > max size {human_size(self.max_file_size)}.")
            self.stats["num_files_filtered"] += 1
            if self.read_content:
                self.check_sensitive_content(share_name, file_path, file_size)
            return

        # Check if the remote file is readable.
        remote_file = self.get_remote_file(share_name, file_path)
        if not remote_file:
            self.logger.fail(f'Cannot read remote file "{file_path}".')
            self.stats["num_get_fail"] += 1
            self.content_status(metadata, "read_error")
            return

        # Check if the file is already downloaded and up-to-date.
        try:
            file_dir, file_name = self.get_file_save_path(remote_file)
        except ValueError as e:
            self.logger.fail(str(e))
            self.stats["num_get_fail"] += 1
            self.content_status(metadata, "download_failed")
            return
        download_path = join(file_dir, file_name)
        needs_update_flag = False
        if exists(download_path):
            if file_modified_time <= stat(download_path).st_mtime and getsize(download_path) == file_size:
                self.logger.info(f'File already downloaded "{file_path}" => "{download_path}".')
                self.stats["num_files_unmodified"] += 1
                if self.sensitive_check or self.content_patterns:
                    self.check_sensitive_content(share_name, file_path, file_size, download_path)
                return
            else:
                needs_update_flag = True

        # Download file.
        download_success = False
        try:
            self.logger.info(f'Downloading file "{file_path}" => "{download_path}".')
            remote_file.open_file()
            download_success = self.save_file(remote_file, share_name, download_path, file_size)
        except SessionError as e:
            self.logger.fail(f'Cannot download file "{file_path}": {e}')
        except Exception as e:
            self.logger.fail(f'Failed to download file "{file_path}". Error: {e!s}')
        finally:
            try:
                remote_file.close()
            except Exception as e:
                self.logger.debug(f"Failed closing downloaded file {file_path}: {e}")

        # Increment stats counters
        if download_success:
            self.stats["num_get_success"] += 1
            if self.sensitive_check or self.content_patterns:
                self.check_sensitive_content(share_name, file_path, file_size, download_path)
            if needs_update_flag:
                self.stats["num_files_updated"] += 1
        else:
            self.stats["num_get_fail"] += 1
            self.content_status(metadata, "download_failed")

    def save_file(self, remote_file, share_name, download_path, expected_size):
        """Save a complete download and remove incomplete or oversized output."""
        # Reset the remote_file to point to the beginning of the file.
        remote_file.seek(0, 0)

        # Create the subdirectories based on the share name and file path.
        folder = Path(download_path).parent
        self.logger.debug(f"Creating folder '{folder}'")
        make_dirs(folder)

        bytes_written = 0
        try:
            with open(download_path, "wb") as fd:
                while True:
                    chunk = self.read_chunk(remote_file, min(CHUNK_SIZE, expected_size + 1 - bytes_written))
                    if not chunk:
                        break
                    bytes_written += len(chunk)
                    if bytes_written > expected_size:
                        raise OSError("File grew beyond its listed size during download")
                    fd.write(chunk)
            if bytes_written != expected_size:
                raise OSError(f"Incomplete download: expected {expected_size} bytes, received {bytes_written}")
        except Exception as e:
            self.logger.fail(f'Error writing file "{download_path}" from share "{share_name}": {e}')
            with suppress(OSError):
                remove(download_path)
            return False
        return True

    def dump_folder_metadata(self, results):
        """Takes the metadata results as input and writes them to a JSON file in the `self.output_folder`.

        The results are formatted with indentation and sorted keys before being written to the file.
        """
        metadata_path = join(self.output_folder, f"{self.output_host}.json")
        try:
            with open(metadata_path, "w", encoding="utf-8") as fd:
                fd.write(json.dumps(results, indent=4, sort_keys=True))
            self.logger.success(f'Saved share-file metadata to "{metadata_path}".')
        except Exception as e:
            self.logger.fail(f"Failed to save share metadata: {e!s}")

    def print_stats(self):
        """Prints the statistics during processing"""
        # Share statistics.
        shares = self.stats.get("shares", [])
        if shares:
            num_shares = len(shares)
            shares_str = ", ".join(shares)
            self.logger.display(f"SMB Shares:           {num_shares} ({shares_str})")
        shares_readable = self.stats.get("shares_readable", [])
        if shares_readable:
            num_readable_shares = len(shares_readable)
            shares_readable_str = ", ".join(shares_readable[:10]) + "..." if len(shares_readable) > 10 else ", ".join(shares_readable)
            self.logger.display(f"SMB Readable Shares:  {num_readable_shares} ({shares_readable_str})")
        shares_writable = self.stats.get("shares_writable", [])
        if shares_writable:
            num_writable_shares = len(shares_writable)
            shares_writable_str = ", ".join(shares_writable[:10]) + "..." if len(shares_writable) > 10 else ", ".join(shares_writable)
            self.logger.display(f"SMB Writable Shares:  {num_writable_shares} ({shares_writable_str})")
        num_shares_filtered = self.stats.get("num_shares_filtered", 0)
        if num_shares_filtered:
            self.logger.display(f"SMB Filtered Shares:  {num_shares_filtered}")

        # Folder statistics.
        num_folders = self.stats.get("num_folders", 0)
        self.logger.display(f"Total folders found:  {num_folders}")
        num_folders_filtered = self.stats.get("num_folders_filtered", 0)
        if num_folders_filtered:
            self.logger.display(f"Folders Filtered:     {num_folders_filtered}")

        # File statistics.
        num_files = self.stats.get("num_files", 0)
        self.logger.display(f"Total files found:    {num_files}")
        if self.sensitive_check:
            self.logger.display(f"Potentially sensitive files: {self.stats['num_sensitive_files']}")
            self.logger.display(f"Files with content indicators: {self.stats['num_sensitive_content_matches']}")
        num_files_filtered = self.stats.get("num_files_filtered", 0)
        if num_files_filtered:
            self.logger.display(f"Files filtered:       {num_files_filtered}")
        if num_files == 0:
            return

        # File sizing statistics.
        file_sizes = self.stats.get("file_sizes", [])
        if file_sizes:
            total_file_size = sum(file_sizes)
            min_file_size = min(file_sizes)
            max_file_size = max(file_sizes)
            average_file_size = total_file_size / num_files
            self.logger.display(f"File size average:    {human_size(average_file_size)}")
            self.logger.display(f"File size min:        {human_size(min_file_size)}")
            self.logger.display(f"File size max:        {human_size(max_file_size)}")

        # Extension statistics.
        file_exts = list(self.stats.get("file_exts", []))
        if file_exts:
            num_unique_file_exts = len(file_exts)
            unique_exts_str = ", ".join(file_exts[:10]) + "..." if len(file_exts) > 10 else ", ".join(file_exts)
            self.logger.display(f"File unique exts:     {num_unique_file_exts} ({unique_exts_str})")

        # Download statistics.
        if self.download_flag:
            num_get_success = self.stats.get("num_get_success", 0)
            if num_get_success:
                self.logger.display(f"Downloads successful: {num_get_success}")
            num_get_fail = self.stats.get("num_get_fail", 0)
            if num_get_fail:
                self.logger.display(f"Downloads failed:     {num_get_fail}")
            num_files_unmodified = self.stats.get("num_files_unmodified", 0)
            if num_files_unmodified:
                self.logger.display(f"Unmodified files:     {num_files_unmodified}")
            num_files_updated = self.stats.get("num_files_updated", 0)
            if num_files_updated:
                self.logger.display(f"Updated files:        {num_files_updated}")
            if num_files_unmodified and not num_files_updated:
                self.logger.display("All files were not changed.")
            if num_files_filtered == num_files:
                self.logger.display("All files were ignored.")
            if num_get_fail == 0:
                self.logger.success("All files processed successfully.")
