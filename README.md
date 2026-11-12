![Supported Python versions](https://img.shields.io/badge/python-3.10+-blue.svg)
[![Twitter](https://img.shields.io/twitter/follow/al3xn3ff?label=al3x_n3ff&style=social)](https://twitter.com/intent/follow?screen_name=al3x_n3ff)
[![Twitter](https://img.shields.io/twitter/follow/_zblurx?label=_zblurx&style=social)](https://twitter.com/intent/follow?screen_name=_zblurx)
[![Twitter](https://img.shields.io/twitter/follow/MJHallenbeck?label=MJHallenbeck&style=social)](https://twitter.com/intent/follow?screen_name=MJHallenbeck)
[![Twitter](https://img.shields.io/twitter/follow/mpgn_x64?label=mpgn_x64&style=social)](https://twitter.com/intent/follow?screen_name=mpgn_x64)


🚩 This is the open source repository of NetExec maintained by a community of passionate people
# NetExec - The Network Execution Tool

This project was initially created in 2015 by @byt3bl33d3r, known as CrackMapExec. In 2019 @mpgn_x64 started maintaining the project for the next 4 years, adding a lot of great tools and features. In September 2023 he retired from maintaining the project.

Along with many other contributors, we (NeffIsBack, Marshall-Hallenbeck, and zblurx) developed new features, bug fixes, and helped maintain the original project CrackMapExec.
During this time, with both a private and public repository, community contributions were not easily merged into the project. The 6-8 month discrepancy between the code bases caused many development issues and heavily reduced community-driven development.
With the end of mpgn's maintainer role, we (the remaining most active contributors) decided to maintain the project together as a fully free and open source project under the new name **NetExec** 🚀
Going forward, our intent is to maintain a community-driven and maintained project with regular updates for everyone to use.

<p align="center">
  <!-- placeholder for nxc logo-->
</p>

You are on the **latest up-to-date** repository of the project NetExec (nxc) ! 🎉

- 🚧 If you want to report a problem, open an [Issue](https://github.com/Pennyw0rth/NetExec/issues) 
- 🔀 If you want to contribute, open a [Pull Request](https://github.com/Pennyw0rth/NetExec/pulls)
- 💬 If you want to discuss, open a [Discussion](https://github.com/Pennyw0rth/NetExec/discussions)

## Official Discord Channel

If you don't have a Github account, you can ask your questions on Discord!

[![NetExec](https://discordapp.com/api/guilds/1148685154601160794/widget.png?style=banner3)](https://discord.gg/pjwUTQzg8R)

# Documentation, Tutorials, Examples
See the project's [wiki](https://netexec.wiki/) (in development) for documentation and usage examples

# Installation
Please see the installation instructions on the [wiki](https://netexec.wiki/getting-started/installation) (in development)

## Linux
```
sudo apt install pipx git
pipx ensurepath
pipx install git+https://github.com/Pennyw0rth/NetExec
```

## Availability on Unix distributions

[![Packaging status](https://repology.org/badge/vertical-allrepos/netexec.svg)](https://repology.org/project/netexec/versions)

# Development
Development guidelines and recommendations in development

## SMB share searches

`spider_plus` inventories readable shares and flags sensitive filenames. Install
the optional `spider` extra to extract document content locally with Kreuzberg
(`uv sync --extra spider`, or install `'.[spider]'` from this checkout with your
package manager). Enable extraction with `DOCUMENTS=True`; add `OCR=True` for
scanned PDFs and images using a local Tesseract installation and language data.
No LLM or cloud service is used.

```sh
netexec smb -M spider_plus --options
netexec smb TARGET_HOST -u LOGIN_USERNAME -p LOGIN_PASSWORD -M spider_plus -o DOCUMENTS=True 'CONTENT_REGEX=password|client_secret' MODIFIED_AFTER=2026-01-01 DEPTH=3
```

Custom searches accept a filename regex, content regex, or a UTF-8 wordlist of
literal terms. Share, extension, directory, date, and depth filters control the
search. Dates use UTC midnight; the lower bound is inclusive and the upper bound
is exclusive. See the module's `--options` output for the option definitions.
Command-line credentials may be visible in process listings and shell history.

The JSON inventory retains built-in indicators under `sensitive` and custom
pattern counts under `search`. Visited files excluded by selection filters have
a `filter_status`; excluded shares/directories are not inventoried. Content
inspection caps both source bytes and extracted UTF-8 bytes with
`SENSITIVE_MAX_FILE_SIZE`. Extraction failures, documents with no extracted text,
and size/type skips are recorded separately from completed checks. Downloads
still save every selected file when `DOWNLOAD_FLAG=True`, including files with
no content matches; cached downloads are inspected without another SMB read.

# Acknowledgments
All the hard work and development over the years from everyone in the CrackMapExec project

# Code Contributors
Awesome code contributors of NetExec:

[![](https://github.com/mpgn.png?size=50)](https://github.com/mpgn)
[![](https://github.com/Marshall-Hallenbeck.png?size=50)](https://github.com/Marshall-Hallenbeck)
[![](https://github.com/zblurx.png?size=50)](https://github.com/zblurx)
[![](https://github.com/NeffIsBack.png?size=50)](https://github.com/NeffIsBack)
[![](https://github.com/Hackndo.png?size=50)](https://github.com/Hackndo)
[![](https://github.com/XiaoliChan.png?size=50)](https://github.com/XiaoliChan)
[![](https://github.com/termanix.png?size=50)](https://github.com/termanix)
[![](https://github.com/Dfte.png?size=50)](https://github.com/Dfte)
[![](https://github.com/azoxlpf.png?size=50)](https://github.com/azoxlpf)
