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
mitmproxy \
--listen-host 127.0.0.1 \
--listen-port 5007 \
--set mitmimage_config='~/mitmimage.yaml' \
--set view_order=size \
--view-filter '~m GET & ~t "(image|video)/(?!svg.xml|x-icon|vnd.microsoft.icon)" & !~websocket' \
-s "$(mitmproxy-image print-path)"
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

mitmproxy-image requires Python 3.9 or above.

To install Python , I recommend using [pyenv](https://github.com/pyenv/pyenv)

## Installation

With [`pipx`](https://github.com/pipxproject/pipx) (recommended):
```bash
python3 -m pip install --user pipx
pipx install https://github.com/rachmadaniHaryono/mitmproxy-image/archive/refs/heads/master.zip
pipx inject --include-apps mitmproxy-image mitmproxy
```

With `pip`:
```bash
python3 -m pip install https://github.com/rachmadaniHaryono/mitmproxy-image/archive/refs/heads/master.zip
```

## Creating desktop file

Edit `$HOME/.local/share/applications/mitmproxy-image.desktop`

```desktop
[Desktop Entry]
Type=Application
Name=mitmproxy-image
Exec=xterm -e mitmproxy -s "$(mitmproxy-image print-path)" --listen-host 127.0.0.1 --listen-port 5007 --view-filter '~m GET & ~t "(image|video)/(?!svg.xml|x-icon|vnd.microsoft.icon)" & !~websocket' --set mitmimage_config='~/mitmimage.yaml' --set view_order=size
```

## Development environment and release process

see CONTRIBUTING.md

This project use modified version of [copier-poetry](https://github.com/pawamoy/copier-poetry/)

## License

This project is licensed under the MIT License
