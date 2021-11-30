# mitmproxy_image

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

## Prerequisites

This is built to be used with Python 3.

To install the program run:

```console
$ # recommended
$ pipx install https://github.com/rachmadaniHaryono/mitmproxy-image/archive/refs/heads/master.zip
$ # or
$ pip3 install https://github.com/rachmadaniHaryono/mitmproxy-image/archive/refs/heads/master.zip
```


## Development environment and release process

 - run tests: `poetry run pytest --flake8 --mypy --doctest-modules`

 - build: `poetry build`

## License

This project is licensed under the MIT License
