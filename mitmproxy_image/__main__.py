#!/usr/bin/env python
"""This script download all the image.

reference:
https://github.com/mitmproxy/mitmproxy/blob/master/examples/simple/internet_in_mirror.py
https://gist.github.com/denschub/2fcc4e03a11039616e5e6e599666f952
https://stackoverflow.com/a/44873382/1766261
"""
import argparse
import asyncio
import logging
import os
import pathlib
import signal
import sys
import typing
from datetime import datetime
from typing import Optional, Union

import click
from appdirs import user_data_dir
from flask import Flask, render_template
from flask.cli import FlaskGroup
from mitmproxy import exceptions, master, options, optmanager
from mitmproxy.tools import cmdline, console, main
from mitmproxy.tools.main import assert_utf8_env, process_options
from mitmproxy.utils import arg_check, debug

from .script import MitmImage

# app dir
APP_DIR = user_data_dir("mitmproxy_image", "rachmadani haryono")
pathlib.Path(APP_DIR).mkdir(parents=True, exist_ok=True)
IMAGE_DIR = os.path.join(APP_DIR, "image")
TEMP_DIR = os.path.join(APP_DIR, "temp")
# log
YEAR = datetime.now().year
MONTH = datetime.now().month
LOG_FILE = os.path.join(APP_DIR, "mitmproxy_image_{}_{}.log".format(YEAR, MONTH))
SERVER_LOG_FILE = os.path.join(
    APP_DIR, "mitmproxy_image_server_{}_{}.log".format(YEAR, MONTH)
)
LOG_FORMAT = "%(asctime)s %(levelname)s - %(name)s:%(message)s"
FORMATTER = logging.Formatter(LOG_FORMAT)
# db
DB_PATH = os.path.abspath(os.path.join(APP_DIR, "mitmproxy_image.db"))
DB_URI = "sqlite:///{}".format(DB_PATH)
# etc
KNOWN_IMAGE_EXTS = (
    "gif",
    "jpeg",
    "jpg",
    "png",
    "svg+xml",
    "vnd.microsoft.icon",
    "webp",
    "x-icon",
)
KNOWN_CONTENT_TYPES = tuple("image/{}".format(x) for x in KNOWN_IMAGE_EXTS)
INVALID_IMAGE_EXTS = ["svg+xml", "x-icon", "gif", "vnd.microsoft.icon", "cur"]
CACHE_SIZE = 1024
LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 5007

# MODEL


def create_app(
    db_uri=DB_URI,
    debug: Optional[bool] = False,
    testing: Optional[bool] = False,
    root_path: Optional[str] = None,
    log_file: Optional[Union[str, None]] = SERVER_LOG_FILE,
) -> Flask:
    """create app."""
    kwargs = {"root_path": root_path} if root_path else {}
    app = Flask(__name__) if not kwargs else Flask(__name__, **kwargs)  # type: ignore
    if log_file:
        fh = logging.FileHandler(log_file)
        fh.setFormatter(FORMATTER)
        if debug:
            fh.setLevel(logging.DEBUG)
        app.logger.addHandler(fh)
    app.config["SWAGGER"] = {"title": "Mitmproxy Image", "uiversion": 2}
    app.config["SECRET_KEY"] = os.urandom(24)
    app.config["WTF_CSRF_ENABLED"] = False
    app.config["SQLALCHEMY_DATABASE_URI"] = db_uri
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    if debug:
        app.config["DEBUG"] = debug
    if testing:
        app.config["TESTING"] = testing
    # folder
    folders = [IMAGE_DIR, TEMP_DIR]
    for folder in folders:
        pathlib.Path(folder).mkdir(parents=True, exist_ok=True)
    # db
    app.app_context().push()

    @app.shell_context_processor
    def shell_context():
        return {
            "app": app,
        }  # pragma: no cover

    # route
    def test():  # pragma: no cover
        app.logger.debug("test page")
        return "hello world"

    app.add_url_rule("/test", "test", test)
    app.add_url_rule("/", "home", lambda: render_template("index.html", title="Home"))
    return app


@click.group(cls=FlaskGroup, create_app=create_app)
def cli():
    """This is a script for application."""
    pass  # pragma: no cover


def run_mitmproxy(
    listen_host: str = LISTEN_HOST,
    listen_port: int = LISTEN_PORT,
    http2=True,
    restart_on_error=True,
):  # pragma: no cover
    """Run mitmproxy.

    based on mitmproxy.main.py and example from following url:
    https://stackoverflow.com/a/62900530/1766261
    """
    opts = main.options.Options(
        listen_host=listen_host, listen_port=listen_port, http2=http2
    )
    master = console.master.ConsoleMaster(opts)
    master.view.focus_follow = True
    if hasattr(main, "proxy"):
        pconf = main.proxy.config.ProxyConfig(opts)  # type: ignore
        master.server = main.proxy.server.ProxyServer(pconf)  # type: ignore
    ao_obj = MitmImage()
    master.addons.add(ao_obj)
    loop = asyncio.get_event_loop()
    loop.add_signal_handler(
        signal.SIGINT, getattr(master, "prompt_for_exit", master.shutdown)
    )
    loop.add_signal_handler(signal.SIGTERM, master.shutdown)
    loop.create_task(ao_obj.upload_worker())
    loop.create_task(ao_obj.post_upload_worker())
    loop.create_task(ao_obj.client_worker())
    if os.name == "nt":

        async def wakeup():
            while True:
                await asyncio.sleep(0.2)

        asyncio.ensure_future(wakeup())
    run = True
    while run:
        try:
            master.run()
            run = False
        except Exception as err:
            logging.debug(str(err), exc_info=True)
            run = True if not restart_on_error else False


@cli.command("run-mitmproxy")
@click.option(
    "--listen-host", show_default=True, default=LISTEN_HOST, help="Host for mitmproxy"
)
@click.option(
    "--listen-port", show_default=True, default=LISTEN_PORT, help="Port for mitmproxy"
)
@click.option("--http2/--no-http2", default=True)
@click.option("--restart/--no-restart", default=True, help="Restart on error.")
def run_mitmproxy_cmd(
    listen_host: str = LISTEN_HOST,
    listen_port: int = LISTEN_PORT,
    http2=True,
    restart=True,
):  # pragma: no cover
    """Run mitmproxy command."""
    run_mitmproxy(listen_host, listen_port, http2, restart_on_error=restart)


def mitmproxy(args=None) -> typing.Optional[int]:  # pragma: no cover
    if os.name == "nt":
        import urwid

        urwid.set_encoding("utf8")
    else:
        assert_utf8_env()
    from mitmproxy.tools import console

    run(console.master.ConsoleMaster, cmdline.mitmproxy, args)
    return None


def run(
    master_cls: typing.Type[master.Master],
    make_parser: typing.Callable[[options.Options], argparse.ArgumentParser],
    arguments: typing.Sequence[str],
    extra: typing.Callable[[typing.Any], dict] = None,
) -> master.Master:  # pragma: no cover
    """
    extra: Extra argument processing callable which returns a dict of
    options.
    """
    debug.register_info_dumpers()

    opts = options.Options()
    master = master_cls(opts)

    parser = make_parser(opts)

    # To make migration from 2.x to 3.0 bearable.
    if "-R" in sys.argv and sys.argv[sys.argv.index("-R") + 1].startswith("http"):
        print("To use mitmproxy in reverse mode please use --mode reverse:SPEC instead")

    try:
        args = parser.parse_args(arguments)
    except SystemExit:
        arg_check.check()
        sys.exit(1)

    try:
        opts.set(*args.setoptions, defer=True)
        optmanager.load_paths(
            opts,
            os.path.join(opts.confdir, "config.yaml"),
            os.path.join(opts.confdir, "config.yml"),
        )
        process_options(parser, opts, args)

        if args.options:
            print(optmanager.dump_defaults(opts))
            sys.exit(0)
        if args.commands:
            master.commands.dump()
            sys.exit(0)
        if extra:
            if args.filter_args:
                master.log.info(
                    f"Only processing flows that match \"{' & '.join(args.filter_args)}\""
                )
            opts.update(**extra(args))

        loop = asyncio.get_event_loop()
        try:
            loop.add_signal_handler(
                signal.SIGINT, getattr(master, "prompt_for_exit", master.shutdown)
            )
            loop.add_signal_handler(signal.SIGTERM, master.shutdown)
        except NotImplementedError:
            # Not supported on Windows
            pass

        # Make sure that we catch KeyboardInterrupts on Windows.
        # https://stackoverflow.com/a/36925722/934719
        if os.name == "nt":

            async def wakeup():
                while True:
                    await asyncio.sleep(0.2)

            asyncio.ensure_future(wakeup())

        master.run()
    except exceptions.OptionsError as e:
        print("{}: {}".format(sys.argv[0], e), file=sys.stderr)
        sys.exit(1)
    except (KeyboardInterrupt, RuntimeError):
        pass
    return master


if __name__ == "__main__":
    cli()  # pragma: no cover
