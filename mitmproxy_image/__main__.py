#!/usr/bin/env python
"""This script download all the image.

reference:
https://github.com/mitmproxy/mitmproxy/blob/master/examples/simple/internet_in_mirror.py
https://gist.github.com/denschub/2fcc4e03a11039616e5e6e599666f952
https://stackoverflow.com/a/44873382/1766261
"""
from datetime import datetime
import hashlib
import os
import pathlib  # require python 3.5+
import shutil
import tempfile

from flask import Flask
from flask.cli import FlaskGroup
from flask_sqlalchemy import SQLAlchemy
from mitmproxy import ctx, http
from PIL import Image  # NOQA
from sqlalchemy.types import TIMESTAMP
from sqlalchemy_utils.types import URLType
import click


def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i + n]


def write_file(flow_item, ext):
    folder = 'image'
    h = hashlib.sha256()
    block = 128*1024
    try:
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_fname = f.name
            with open(temp_fname, 'wb', buffering=0) as f:
                for b in chunks(flow_item.response.content, block):
                    h.update(b)
                    f.write(b)
            sha256_csum = h.hexdigest()
            new_bname = '{}.{}'.format(sha256_csum, ext)
            parent_folder = os.path.join(folder, sha256_csum[:2])
            new_fname = os.path.join(parent_folder, new_bname)
            pathlib.Path(parent_folder).mkdir(parents=True, exist_ok=True)
            shutil.move(temp_fname, new_fname)
        ctx.log.info('DONE:{}'.format(new_fname))
    except Exception as e:
        ctx.log.error('url: {}'.format(flow_item.request.pretty_url))
        ctx.log.error('{}:{}'.format(type(e), e))


def response(flow: http.HTTPFlow) -> None:
    if 'content-type' in flow.response.headers:
        content_type = flow.response.headers['content-type']
        if content_type.startswith('image'):
            # check in database
            in_databse = False
            if not in_databse:
                ext = content_type.split('/')[1].split(';')[0]
                invalid_exts = ['svg+xml', 'x-icon', 'gif']
                if ext not in invalid_exts:
                    write_file(flow, ext)

                    # send to server
                    req_url = flow.request.pretty_url  # NOQA
                    #  sha256_csum
                    #  ext


# MODEL
db = SQLAlchemy()


class Base(db.Model):
    __abstract__ = True
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(TIMESTAMP, default=datetime.now, nullable=False)


class Sha256Checksum(Base):
    value = db.Column(db.String, unique=True)
    ext = db.Column(db.String)
    filesize = db.Column(db.Integer)
    height = db.Column(db.Integer)
    width = db.Column(db.Integer)
    img_format = db.Column(db.String)
    img_mode = db.Column(db.String)
    urls = db.relationship('Url', lazy='subquery', backref='checksum')
    trash = db.Column(db.Boolean, default=False)


class Url(Base):
    value = db.Column(URLType, unique=True, nullable=False)


# FLASK
def create_app(script_info=None):
    """create app."""
    app = Flask(__name__)
    database_path = 'mitmproxy_image.db'
    database_uri = 'sqlite:///' + database_path
    app.config['SQLALCHEMY_DATABASE_URI'] = database_uri # NOQA
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = os.urandom(24)
    app.config['WTF_CSRF_ENABLED'] = False

    # app and db
    db.init_app(app)
    app.app_context().push()
    db.create_all()

    @app.shell_context_processor
    def shell_context():
        return {
            'app': app, 'db': db, 'session': db.session,
            'Sha256Checksum': Sha256Checksum, 'Url': 'Url'
        }
    return app


@click.group(cls=FlaskGroup, create_app=create_app)
def cli():
    """This is a script for application."""
    pass


@cli.command('echo-path')
def echo_path():
    'Echo path to script.'
    print(__file__)


if __name__ == '__main__':
    cli()
