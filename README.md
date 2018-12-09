# mitmproxy_image

Download image using mitmproxy


## Quick Start

To run it, set your browser for mitmproxy.
Here are example command to run it on host `127.0.0.1` and port `5007`:

```console
$ mitmproxy --listen-host 127.0.0.1 --listen-port 5007 -s $(mitmproxy-image echo-path)
```

To Run the application on host `127.0.0.1` and port `5012`, run following command:

```console
$ mitmproxy-image run -p 5012 --debugger
```

And open it in the browser at [http://127.0.0.1:5012/](http://127.0.0.1:5000/)


To redirect your browser to downloaded image on your self hosted server,
add `redirect_host` and `redirect_port` arguments. Example for above configuration:

```console
$ mitmproxy --listen-host 127.0.0.1 --listen-port 5007 -s $(mitmproxy-image echo-path) --set redirect_host=127.0.0.1 --set redirect_port=5012
```

To use it with hydrus, run the server as stated above and import the downloaders script.


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

 - run development server in debug mode: `mitmproxy-image run --debug`; Flask will restart if source code is modified

 - run tests: tba

 - create source distribution: `python setup.py sdist`

License
This project is licensed under the MIT License
