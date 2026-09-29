from os.path import abspath, join
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
        Filename hints are enabled by default. Successful/cached downloads are also checked for sensitive content.
        Set SENSITIVE_CHECK_STATICONLY=False to read eligible remote text files without saving them.
        Content matches are indicators for review, not proof of valid credentials. Binary/Office files are not parsed.
        Filename hints do not establish readability. Text checks support UTF-8 and UTF-16 with a byte order mark.
        JSON metadata records name_matches, content_matches, content_status, and bytes_checked under sensitive.
        Content checks require a complete file within the size limit; exclusions and read failures remain unchecked.
        No content match does not establish that a file is safe or remove a filename hint.

        DOWNLOAD_FLAG     Download all share folders/files (Default: False)
        STATS_FLAG        Print file/download statistics (Default: True)
        EXCLUDE_EXTS      Extensions excluded from downloads/content reads (Default: ico,lnk)
        EXCLUDE_FILTER    Case-insensitive filter to exclude folders/files (Default: print$,ipc$)
        MAX_FILE_SIZE     Max file size to download (Default: 51200)
        OUTPUT_FOLDER     Path of the local folder to save files (Default: NXC_PATH/modules/nxc_spider_plus)
        SENSITIVE_CHECK_ENABLE        Flag potentially sensitive files (Default: True)
        SENSITIVE_CHECK_STATICONLY    Avoid extra remote content reads; downloads are still checked (Default: True)
        SENSITIVE_CHECK_MAX_FILE_SIZE Max file size in bytes for content checks (Default: 1048576)
        """
        for key, default in (("DOWNLOAD_FLAG", "False"), ("STATS_FLAG", "True"), ("SENSITIVE_CHECK_ENABLE", "True"), ("SENSITIVE_CHECK_STATICONLY", "True")):
            value = module_options.get(key, default).lower()
            if value not in ("true", "false"):
                context.log.fail(f"{key} must be True or False")
                exit(1)
            setattr(self, key.lower(), value == "true")
        self.exclude_exts = get_list_from_option(module_options.get("EXCLUDE_EXTS", "ico,lnk"))
        self.exclude_filter = get_list_from_option(module_options.get("EXCLUDE_FILTER", "print$,ipc$"))
        self.max_file_size = int(module_options.get("MAX_FILE_SIZE", 50 * 1024))
        try:
            self.sensitive_check_max_file_size = int(module_options.get("SENSITIVE_CHECK_MAX_FILE_SIZE", 1024 * 1024))
            if self.sensitive_check_max_file_size <= 0:
                raise ValueError
        except ValueError:
            context.log.fail("SENSITIVE_CHECK_MAX_FILE_SIZE must be a positive number of bytes")
            exit(1)
        self.output_folder = module_options.get("OUTPUT_FOLDER", abspath(join(NXC_PATH, "modules/nxc_spider_plus")))

    def on_login(self, context, connection):
        context.log.display("Started module spidering_plus with the following options:")
        context.log.display(f" DOWNLOAD_FLAG: {self.download_flag}")
        context.log.display(f"    STATS_FLAG: {self.stats_flag}")
        context.log.display(f"EXCLUDE_FILTER: {self.exclude_filter}")
        context.log.display(f"  EXCLUDE_EXTS: {self.exclude_exts}")
        context.log.display(f" MAX_FILE_SIZE: {human_size(self.max_file_size)}")
        context.log.display(f" OUTPUT_FOLDER: {self.output_folder}")
        context.log.display(f"       SENSITIVE_CHECK_ENABLE: {self.sensitive_check_enable}")
        context.log.display(f"   SENSITIVE_CHECK_STATICONLY: {self.sensitive_check_staticonly}")
        context.log.display(f"SENSITIVE_CHECK_MAX_FILE_SIZE: {human_size(self.sensitive_check_max_file_size)}")

        spider = SMBSpiderPlus(
            connection,
            context.log,
            self.download_flag,
            self.stats_flag,
            self.exclude_exts,
            self.exclude_filter,
            self.max_file_size,
            self.output_folder,
            sensitive_check_enable=self.sensitive_check_enable,
            sensitive_check_staticonly=self.sensitive_check_staticonly,
            sensitive_check_max_file_size=self.sensitive_check_max_file_size,
        )

        spider.spider_shares()
