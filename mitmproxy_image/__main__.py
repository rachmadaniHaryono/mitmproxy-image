#!/usr/bin/env python
"""This script download all the image.

reference:
https://github.com/mitmproxy/mitmproxy/blob/master/examples/simple/internet_in_mirror.py
https://gist.github.com/denschub/2fcc4e03a11039616e5e6e599666f952
https://stackoverflow.com/a/44873382/1766261
"""
import asyncio
import logging
import os
import pathlib
import shlex
import signal
from datetime import datetime
from typing import Optional, Union

import click
from appdirs import user_data_dir
from flask import Flask, render_template
from flask.cli import FlaskGroup
from mitmproxy.tools import console, main

from .script import MitmImage

# app dir
APP_DIR = user_data_dir('mitmproxy_image', 'rachmadani haryono')
pathlib.Path(APP_DIR).mkdir(parents=True, exist_ok=True)
IMAGE_DIR = os.path.join(APP_DIR, 'image')
TEMP_DIR = os.path.join(APP_DIR, 'temp')
# log
YEAR = datetime.now().year
MONTH = datetime.now().month
LOG_FILE = os.path.join(
    APP_DIR, 'mitmproxy_image_{}_{}.log'.format(YEAR, MONTH))
SERVER_LOG_FILE = os.path.join(
    APP_DIR, 'mitmproxy_image_server_{}_{}.log'.format(YEAR, MONTH))
LOG_FORMAT = '%(asctime)s %(levelname)s - %(name)s:%(message)s'
FORMATTER = logging.Formatter(LOG_FORMAT)
# db
DB_PATH = os.path.abspath(os.path.join(APP_DIR, 'mitmproxy_image.db'))
DB_URI = 'sqlite:///{}'.format(DB_PATH)
# etc
KNOWN_IMAGE_EXTS = (
    'gif', 'jpeg', 'jpg', 'png', 'svg+xml', 'vnd.microsoft.icon',
    'webp', 'x-icon',)
KNOWN_CONTENT_TYPES = tuple('image/{}'.format(x) for x in KNOWN_IMAGE_EXTS)
INVALID_IMAGE_EXTS = ['svg+xml', 'x-icon', 'gif', 'vnd.microsoft.icon', 'cur']
CACHE_SIZE = 1024
LISTEN_HOST = '127.0.0.1'
LISTEN_PORT = 5007

# MODEL


def create_app(
        db_uri=DB_URI,
        debug: Optional[bool] = False,
        testing: Optional[bool] = False,
        root_path: Optional[str] = None,
        log_file: Optional[Union[str, None]] = SERVER_LOG_FILE
) -> Flask:
    """create app."""
    kwargs = {'root_path': root_path} if root_path else {}
    app = \
        Flask(__name__) \
        if not kwargs else Flask(__name__, **kwargs)  # type: ignore
    if log_file:
        fh = logging.FileHandler(log_file)
        fh.setFormatter(FORMATTER)
        if debug:
            fh.setLevel(logging.DEBUG)
        app.logger.addHandler(fh)
    app.config['SWAGGER'] = {
        'title': 'Mitmproxy Image',
        'uiversion': 2
    }
    app.config['SECRET_KEY'] = os.urandom(24)
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    if debug:
        app.config['DEBUG'] = debug
    if testing:
        app.config['TESTING'] = testing
    # folder
    folders = [IMAGE_DIR, TEMP_DIR]
    for folder in folders:
        pathlib.Path(folder).mkdir(parents=True, exist_ok=True)
    # db
    app.app_context().push()

    @app.shell_context_processor
    def shell_context():
        return {'app': app, }  # pragma: no cover

    # route
    def test():  # pragma: no cover
        app.logger.debug('test page')
        return 'hello world'
    app.add_url_rule('/test', 'test', test)
    app.add_url_rule('/', 'home', lambda: render_template('index.html', title='Home'))
    return app


@click.group(cls=FlaskGroup, create_app=create_app)
def cli():
    """This is a script for application."""
    pass  # pragma: no cover


@cli.command('run-mitmproxy')
@click.option(
    '--listen-host',
    show_default=True, default=LISTEN_HOST, help='Host for mitmproxy')
@click.option(
    '--listen-port',
    show_default=True, default=LISTEN_PORT, help='Port for mitmproxy')
def run_mitmproxy_cmd(
        listen_host: str = LISTEN_HOST,
        listen_port: int = LISTEN_PORT
):
    """Run mitmproxy.

    based on mitmproxy.main.py and example from following url:
    https://stackoverflow.com/a/62900530/1766261
    """
    opts = main.options.Options(listen_host=listen_host, listen_port=listen_port)
    master = console.master.ConsoleMaster(opts)
    master.view.focus_follow = True
    pconf = main.proxy.config.ProxyConfig(opts)
    master.server = main.proxy.server.ProxyServer(pconf)
    ao_obj = MitmImage()
    ao_obj.load_config(ao_obj.default_config_path)
    master.addons.add(ao_obj)
    loop = asyncio.get_event_loop()
    loop.add_signal_handler(signal.SIGINT, getattr(master, "prompt_for_exit", master.shutdown))
    loop.add_signal_handler(signal.SIGTERM, master.shutdown)
    loop.create_task(ao_obj.upload_worker())
    loop.create_task(ao_obj.post_upload_worker())
    loop.create_task(ao_obj.client_worker())
    master.run()
    return master


if __name__ == '__main__':
    cli()  # pragma: no cover
