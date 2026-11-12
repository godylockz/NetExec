#!/usr/bin/env python3
# -- coding: utf-8 --

# Imports
import re
from datetime import UTC, datetime
from os.path import abspath, join
from pathlib import Path
from sys import exit

from nxc.helpers.misc import CATEGORY
from nxc.paths import NXC_PATH
from nxc.protocols.smb.spiderplus import SMBSpiderPlus, get_list_from_option, human_size


class NXCModule:
    """Spider Plus Module

    Module by @vincd
    Updated by @godylockz
    """

    name = "spider_plus"
    description = "List share files, flag potentially sensitive files, and save JSON metadata."
    supported_protocols = ["smb"]
    category = CATEGORY.CREDENTIAL_DUMPING

    def options(self, context, module_options):
        """
        List files recursively and save JSON share-file metadata to OUTPUT_FOLDER.
        Filename checks are enabled by default. When SENSITIVE_CHECK=True, successful/cached downloads are also inspected within the content size limit.
        Set SENSITIVE_READ_CONTENT=True to read eligible remote text files without saving them.
        DOCUMENTS=True also reads and extracts Office/PDF text. OCR=True enables local Tesseract OCR.
        CONTENT_REGEX or CONTENT_WORDLIST enables remote content searches independently of SENSITIVE_CHECK.
        Content matches are indicators for review, not proof of valid credentials.
        Filename hints do not establish readability. Text checks support UTF-8 and UTF-16 with a byte order mark.
        JSON metadata records name_matches, content_matches, content_status, and bytes_checked under sensitive.
        Content checks require a complete file within the size limit; exclusions and read failures remain unchecked.
        No content match does not establish that a file is safe or remove a filename hint.

        DOWNLOAD_FLAG     Download all selected files, including content nonmatches (Default: False)
        STATS_FLAG        Print file/download statistics (Default: True)
        EXCLUDE_EXTS      Extensions excluded from downloads/content reads (Default: ico,lnk)
        EXCLUDE_FILTER    Case-insensitive filter to exclude folders/files (Default: print$,ipc$)
        MAX_FILE_SIZE     Max file size to download (Default: 51200)
        OUTPUT_FOLDER     Path of the local folder to save files (Default: NXC_PATH/modules/nxc_spider_plus)
        SENSITIVE_CHECK        Flag potentially sensitive files (Default: True)
        SENSITIVE_READ_CONTENT  Also read eligible remote files for content checks (Default: False)
        SENSITIVE_MAX_FILE_SIZE Max file size in bytes for content checks (Default: 1048576)
        DOCUMENTS         Extract PDF, Office, ODT/ODS and RTF content; requires netexec[spider] (Default: False)
        OCR               Enable Tesseract OCR for scanned PDFs/images; requires DOCUMENTS=True (Default: False)
        NAME_REGEX        Case-insensitive filename regex; also filters content reads/downloads
        CONTENT_REGEX     Case-insensitive content regex (combine alternatives with |)
        CONTENT_WORDLIST  Local UTF-8 file of literal search terms, one per line; blank lines/# comments ignored
        SHARES            Comma-separated share names to search (Default: all enumerated readable shares)
        INCLUDE_EXTS      Comma-separated extensions to search (Default: all; use <none> for extensionless files)
        INCLUDE_DIRS      Comma-separated directory path substrings; ancestors are traversed to reach matches
        EXCLUDE_DIRS      Comma-separated directory path substrings to skip
        DEPTH             Maximum directory depth; 0 searches only share roots (Default: unlimited)
        MODIFIED_AFTER    Include files modified on/after YYYY-MM-DD at 00:00 UTC
        MODIFIED_BEFORE   Include files modified before YYYY-MM-DD at 00:00 UTC
        Filters combine with AND; content terms combine with OR. JSON retains metadata for filtered files.
        Documents obey SENSITIVE_MAX_FILE_SIZE. Extraction is local; archives/encrypted stores are skipped.
        """
        for key, default in (("DOWNLOAD_FLAG", "False"), ("STATS_FLAG", "True"), ("SENSITIVE_CHECK", "True"), ("SENSITIVE_READ_CONTENT", "False"), ("DOCUMENTS", "False"), ("OCR", "False")):
            value = module_options.get(key, default).lower()
            if value not in ("true", "false"):
                context.log.fail(f"{key} must be True or False")
                exit(1)
            setattr(self, key.lower(), value == "true")
        self.exclude_exts = get_list_from_option(module_options.get("EXCLUDE_EXTS", "ico,lnk"))
        self.exclude_filter = get_list_from_option(module_options.get("EXCLUDE_FILTER", "print$,ipc$"))
        self.max_file_size = int(module_options.get("MAX_FILE_SIZE", 50 * 1024))
        try:
            self.sensitive_max_file_size = int(module_options.get("SENSITIVE_MAX_FILE_SIZE", 1024 * 1024))
            if self.sensitive_max_file_size <= 0:
                raise ValueError
        except ValueError:
            context.log.fail("SENSITIVE_MAX_FILE_SIZE must be a positive number of bytes")
            exit(1)
        self.output_folder = module_options.get("OUTPUT_FOLDER", abspath(join(NXC_PATH, "modules/nxc_spider_plus")))
        try:
            self.name_regex = re.compile(module_options["NAME_REGEX"], re.IGNORECASE) if "NAME_REGEX" in module_options else None
            self.content_patterns = [re.compile(module_options["CONTENT_REGEX"], re.IGNORECASE)] if "CONTENT_REGEX" in module_options else []
            if "CONTENT_WORDLIST" in module_options:
                self.content_patterns.extend(re.compile(re.escape(term.strip()), re.IGNORECASE) for term in Path(module_options["CONTENT_WORDLIST"]).read_text(encoding="utf-8-sig").splitlines() if term.strip() and not term.lstrip().startswith("#"))
                if not self.content_patterns:
                    raise ValueError("CONTENT_WORDLIST contains no search terms")
            self.depth = int(module_options["DEPTH"]) if "DEPTH" in module_options else None
            if self.depth is not None and self.depth < 0:
                raise ValueError("DEPTH must be zero or greater")
            self.modified_after = datetime.strptime(module_options["MODIFIED_AFTER"], "%Y-%m-%d").replace(tzinfo=UTC).timestamp() if "MODIFIED_AFTER" in module_options else None
            self.modified_before = datetime.strptime(module_options["MODIFIED_BEFORE"], "%Y-%m-%d").replace(tzinfo=UTC).timestamp() if "MODIFIED_BEFORE" in module_options else None
            if self.modified_after is not None and self.modified_before is not None and self.modified_after >= self.modified_before:
                raise ValueError("MODIFIED_AFTER must precede MODIFIED_BEFORE")
        except (OSError, UnicodeError, ValueError, re.error) as e:
            context.log.fail(f"Invalid spider search option: {e}")
            exit(1)
        self.shares = get_list_from_option(module_options.get("SHARES", ""))
        self.include_exts = [ext.lstrip(".") for ext in get_list_from_option(module_options.get("INCLUDE_EXTS", ""))]
        self.include_dirs = get_list_from_option(module_options.get("INCLUDE_DIRS", ""))
        self.exclude_dirs = get_list_from_option(module_options.get("EXCLUDE_DIRS", ""))
        if self.ocr and not self.documents:
            context.log.fail("OCR=True requires DOCUMENTS=True")
            exit(1)
        if self.documents and not SMBSpiderPlus.document_parser_available():
            context.log.fail("DOCUMENTS=True requires the spider extra: install netexec[spider]")
            exit(1)

    def on_login(self, context, connection):
        context.log.display("Started module spidering_plus with the following options:")
        context.log.display(f" DOWNLOAD_FLAG: {self.download_flag}")
        context.log.display(f"    STATS_FLAG: {self.stats_flag}")
        context.log.display(f"EXCLUDE_FILTER: {self.exclude_filter}")
        context.log.display(f"  EXCLUDE_EXTS: {self.exclude_exts}")
        context.log.display(f" MAX_FILE_SIZE: {human_size(self.max_file_size)}")
        context.log.display(f" OUTPUT_FOLDER: {self.output_folder}")
        context.log.display(f"        SENSITIVE_CHECK: {self.sensitive_check}")
        context.log.display(f" SENSITIVE_READ_CONTENT: {self.sensitive_read_content}")
        context.log.display(f"SENSITIVE_MAX_FILE_SIZE: {human_size(self.sensitive_max_file_size)}")
        context.log.display(f"DOCUMENTS: {self.documents}, OCR: {self.ocr}")
        for key in ("name_regex", "content_patterns", "shares", "include_exts", "include_dirs", "exclude_dirs", "depth", "modified_after", "modified_before"):
            value = getattr(self, key)
            if value is not None and value != []:
                context.log.display(f"{key.upper()}: {value}")

        spider = SMBSpiderPlus(
            connection,
            context.log,
            self.download_flag,
            self.stats_flag,
            self.exclude_exts,
            self.exclude_filter,
            self.max_file_size,
            self.output_folder,
            sensitive_check=self.sensitive_check,
            sensitive_read_content=self.sensitive_read_content,
            sensitive_max_file_size=self.sensitive_max_file_size,
            documents=self.documents,
            ocr=self.ocr,
            name_regex=self.name_regex,
            content_patterns=self.content_patterns,
            shares=self.shares,
            include_exts=self.include_exts,
            include_dirs=self.include_dirs,
            exclude_dirs=self.exclude_dirs,
            depth=self.depth,
            modified_after=self.modified_after,
            modified_before=self.modified_before,
        )

        spider.spider_shares()
