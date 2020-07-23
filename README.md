# magic-yara-python

This is a fork of the official `yara-python` library developed by VirusTotal
([GitHub](https://github.com/VirusTotal/yara-python),
[PyPI](https://pypi.org/project/yara-python/),
[documentation](https://yara.readthedocs.org/en/latest/yarapython.html)).

It introduces no functional differences but enables the following YARA modules
by default:

- [magic](https://yara.readthedocs.io/en/latest/modules/magic.html)
- [dotnet](https://yara.readthedocs.io/en/latest/modules/dotnet.html)

In other words, installing `magic-yara-python` is equivalent to installing
`yara-python` with the `--enable-magic --enable-dotnet` flags.

The reason this fork exists is that it is sometimes hard or inconvenient to
provide these flags, depending on your method of installation. For example,
`setuptools` provides no means to supply additional build options for its
`install_requires` entries. If you install via `pip` you can set these options
through `--global-option` flags, but that becomes unwieldy quickly.
`magic-yara-python` is meant as an easy workaround for these cases.
