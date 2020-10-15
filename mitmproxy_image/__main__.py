#!/usr/bin/env python
"""This script download all the image.

reference:
https://github.com/mitmproxy/mitmproxy/blob/master/examples/simple/internet_in_mirror.py
https://gist.github.com/denschub/2fcc4e03a11039616e5e6e599666f952
https://stackoverflow.com/a/44873382/1766261
"""
import logging
import os
import pathlib
import shlex
from datetime import datetime
from typing import Optional, Union

import click
import yaml
from appdirs import user_data_dir
from flask import Flask
from flask.cli import FlaskGroup
from mitmproxy.tools._main import mitmproxy

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
        return {'app': app, }

    # route
    def test():
        app.logger.debug('test page')
        return 'hello world'
    app.add_url_rule('/test', 'test', test)

    def home():
        return 'Mitmproxy-Image'
    app.add_url_rule('/', 'home', home)
    return app


@click.group(cls=FlaskGroup, create_app=create_app)
def cli():
    """This is a script for application."""
    pass


@cli.command('run-mitmproxy')
@click.option(
    '--listen-host',
    show_default=True, default='127.0.0.1', help='Host for mitmproxy')
@click.option(
    '--listen-port',
    show_default=True, default=5007, help='Host for mitmproxy')
def run_mitmproxy(
        listen_host: Optional[str] = '127.0.0.1',
        listen_port: Optional[int] = 5007,
):
    args_lines = ['--listen-host {}'.format(listen_host)]
    if listen_port:
        args_lines.append('--listen-port {}'.format(listen_port))
    args_lines.append('-s {}'.format(os.path.join(
        os.path.dirname(__file__), 'script.py')))
    view_filter = '~t "(image\\/(?!cur|svg.xml|vnd.microsoft.icon|x-icon).+)|' \
        'video\\/(mp2t|MP2T|webm)"'
    config_path = os.path.expanduser('~/mitmimage.yaml')
    if os.path.isfile(config_path):
        with open(config_path) as f:
            config_view_filter = yaml.safe_load(f).get('view_filter', None)
            if config_view_filter:
                view_filter = config_view_filter
                print('view filter:{}'.format(config_view_filter))
    args_lines.append('--view-filter {}'.format(shlex.quote(view_filter)))

    args_lines.append(
        '--set console_focus_follow={}'.format(shlex.quote('true')))
    mitmproxy(shlex.split(' '.join(args_lines)))


if __name__ == '__main__':
    cli()
