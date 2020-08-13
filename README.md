# mitmproxy_image

Download image using mitmproxy on hydrus.


## Quick Start

- Set up your browser for mitmproxy or
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

 - run tests: tba

 - create source distribution: `python setup.py sdist`

License
This project is licensed under the MIT License
