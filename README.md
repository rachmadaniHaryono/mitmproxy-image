# mitmproxy-image

<!-- [![ci](https://github.com/rachmadaniHaryono/mitmproxy-image/workflows/ci/badge.svg)](https://github.com/rachmadaniHaryono/mitmproxy-image/actions?query=workflow%3Aci) -->
<!-- [![documentation](https://img.shields.io/badge/docs-mkdocs%20material-blue.svg?style=flat)](https://rachmadaniHaryono.github.io/mitmproxy-image/) -->
<!-- [![pypi version](https://img.shields.io/pypi/v/mitmproxy-image.svg)](https://pypi.org/project/mitmproxy-image/) -->
<!-- [![gitter](https://badges.gitter.im/join%20chat.svg)](https://gitter.im/mitmproxy-image/community) -->
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

Download image using mitmproxy on hydrus.

## Quick Start

- Set up your browser for mitmproxy ([guide](https://docs.mitmproxy.org/stable/overview-getting-started/)) or
use extension such as [SwitchyOmega](https://github.com/FelisCatus/SwitchyOmega)

- Run the application

```console
$ mitmproxy-image
$ # another example
$ mitmproxy-image \
--listen-host 127.0.0.1 \
--listen-port 5007 \
--set hydrus_access_key=$HYDRUS_ACCESS_KEY \
--view-filter '~m GET & ~t "(audio|image|video)" & !~websocket'
```

If configuration is succesful,
each time your browser load an image
it will also be shown on `mitmimage` downloader page on hydrus.

Downloaded image is not presented as new files,
so change presentation option on `mitmimage` downloader page.

It is also recommended to install browser extension that will load bigger image,
such as imagus (
[chrome](https://chrome.google.com/webstore/detail/imagus/immpkjjlgappgfkkfieppnmlhakdmaab?hl=en),
[firefox](https://addons.mozilla.org/en-US/firefox/addon/imagus/)
) or maxurl (
[firefox](https://addons.mozilla.org/en-US/firefox/addon/image-max-url/),
[github](https://github.com/qsniyg/maxurl)
)

![demo](https://user-images.githubusercontent.com/6340878/111593026-776fe280-8804-11eb-904e-1a1ae0ac960e.gif)

note: the appearance, command line and hydrus version may differ from actual version,
but the workflow is as shown on the gif.

## Requirements

mitmproxy-image requires Python 3.8 or above.

<details>
<summary>To install Python 3.8, I recommend using <a href="https://github.com/pyenv/pyenv"><code>pyenv</code></a>.</summary>

```bash
# install pyenv
git clone https://github.com/pyenv/pyenv ~/.pyenv

# setup pyenv (you should also put these three lines in .bashrc or similar)
export PATH="${HOME}/.pyenv/bin:${PATH}"
export PYENV_ROOT="${HOME}/.pyenv"
eval "$(pyenv init -)"

# install Python 3.8
pyenv install 3.8

# make it available globally
pyenv global system 3.8
```
</details>

## Installation

With [`pipx`](https://github.com/pipxproject/pipx) (recommended):
```bash
python3.8 -m pip install --user pipx

pipx install --python python3.8 https://github.com/rachmadaniHaryono/mitmproxy-image/archive/refs/heads/master.zip
```

With `pip`:
```bash
python3.8 -m pip install https://github.com/rachmadaniHaryono/mitmproxy-image/archive/refs/heads/master.zip
```

## Development environment and release process

- `poetry install`, setup project with poetry
- `make format`, to auto-format the code
- `make test`, to run the test suite
- `make check`, to check if everything is OK
- `make changelog`, to update the changelog
- `make release version=x.y.z`, to release a version

This project use modified version of [copier-poetry](https://github.com/pawamoy/copier-poetry/)

## License

This project is licensed under the MIT License
