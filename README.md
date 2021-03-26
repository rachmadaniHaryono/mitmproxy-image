# mitmproxy_image

Download image using mitmproxy on hydrus.


## Quick Start

- Set up your browser for mitmproxy ([guide](https://docs.mitmproxy.org/stable/overview-getting-started/)) or
use extension such as [SwitchyOmega](https://github.com/FelisCatus/SwitchyOmega)

- Run the application (by default it will use `127.0.0.1:5007`):

```console
$ mitmproxy-image run-mitmproxy
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
)

![demo](https://user-images.githubusercontent.com/6340878/111593026-776fe280-8804-11eb-904e-1a1ae0ac960e.gif)

## Prerequisites

This is built to be used with Python 3.

To install the program run:

```console
$ pip install .
$ # or
$ python setup.py install
```


## Development environment and release process

 - create virtualenv with Flask and mitmproxy_image installed into it (latter is installed in
   [develop mode](http://setuptools.readthedocs.io/en/latest/setuptools.html#development-mode) which allows
   modifying source code directly without a need to re-install the app): `make venv`

 - run tests: `pytest --flake8 --mypy --doctest-modules .`

 - create source distribution: `python setup.py sdist`

 ## License

This project is licensed under the MIT License
