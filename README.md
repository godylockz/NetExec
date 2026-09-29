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

## Sensitive files in SMB shares

`spider_plus` flags potentially sensitive filenames by default, including credential configs,
private key containers, password vaults, credential stores, and command histories.
Filename hints do not prove that a file contains credentials or that the current user can read it.

```sh
netexec smb TARGET_HOST -u LOGIN_USERNAME -p LOGIN_PASSWORD -M spider_plus
netexec smb TARGET_HOST -u LOGIN_USERNAME -p LOGIN_PASSWORD -M spider_plus -o SENSITIVE_CHECK_STATICONLY=False
netexec smb TARGET_HOST -u LOGIN_USERNAME -p LOGIN_PASSWORD -M spider_plus -o DOWNLOAD_FLAG=True
netexec smb -M spider_plus --options
```

`SENSITIVE_CHECK_STATICONLY=True` avoids extra remote content reads. Successful downloads and
unchanged cached downloads are checked automatically. Set it to `False` to read candidate text
files without saving them. `SENSITIVE_CHECK_MAX_FILE_SIZE` limits content checks to whole files of
at most 1048576 bytes by default; `MAX_FILE_SIZE` remains the separate download limit.
`SENSITIVE_CHECK_ENABLE=False` disables both filename and content checks.

Each file's existing JSON metadata gains a `sensitive` entry with `name_matches`, `content_matches`,
`content_status`, and `bytes_checked`. A `checked` file with no content matches still retains any
filename hint. Excluded extensions, oversized files, binary files, changed sizes, and read failures
are recorded as unchecked. Text checks support UTF-8 and UTF-16 with a byte order mark and look for
credential values, connection URIs, and private key material. They do not parse Office documents,
archives, encrypted stores, or arbitrary encodings; no match does not establish that a file is safe.

The curated indicators were informed by [SauronEye](https://github.com/vivami/SauronEye),
[needle](https://github.com/blurbdust/needle), [LaZagne](https://github.com/AlessandroZ/LaZagne),
[SnafflePy](https://github.com/S3cur3Th1sSh1t/SnafflePy), and [Snaffler](https://github.com/SnaffCon/Snaffler).

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
