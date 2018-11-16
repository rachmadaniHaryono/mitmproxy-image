#!/usr/bin/env python
"""This script download all the image.

reference:
https://github.com/mitmproxy/mitmproxy/blob/master/examples/simple/internet_in_mirror.py
https://gist.github.com/denschub/2fcc4e03a11039616e5e6e599666f952
https://stackoverflow.com/a/44873382/1766261
"""
from datetime import datetime
from io import BytesIO
import hashlib
import os
import pathlib  # require python 3.5+
import shutil
import tempfile

from flask import Flask
from flask.cli import FlaskGroup
from flask_sqlalchemy import SQLAlchemy
from mitmproxy import ctx, http
from PIL import Image
from sqlalchemy.types import TIMESTAMP
from sqlalchemy_utils.types import URLType
import click


def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i + n]


def process_flow(flow_item, ext):
    folder = 'image'
    h = hashlib.sha256()
    block = 128*1024
    s = BytesIO()
    res = {}
    try:
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_fname = f.name
            with open(temp_fname, 'wb', buffering=0) as f:
                for b in chunks(flow_item.response.content, block):
                    h.update(b)
                    f.write(b)
                    s.write(b)
                img = Image.open(s)
            s.seek(0, os.SEEK_END)
            filesize = s.tell()
            sha256_csum = h.hexdigest()
            new_bname = '{}.{}'.format(sha256_csum, ext)
            parent_folder = os.path.join(folder, sha256_csum[:2])
            new_fname = os.path.join(parent_folder, new_bname)
            pathlib.Path(parent_folder).mkdir(parents=True, exist_ok=True)
            shutil.move(temp_fname, new_fname)
        ctx.log.info('DONE:{}'.format(new_fname))
        res = {
            'value': sha256_csum,
            'filesize': filesize,
            'ext': ext,
            'width': img.size[0],
            'height': img.size[1],
            'img_format': img.format,
            'img_mode': img.mode
        }
    except Exception as e:
        ctx.log.error('url: {}'.format(flow_item.request.pretty_url))
        ctx.log.error('{}:{}'.format(type(e), e))
    return res


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
    sha256_checksum_id = db.Column(
        db.Integer, db.ForeignKey('sha256_checksum.id'))


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
            'Sha256Checksum': Sha256Checksum, 'Url': Url,
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


def save_info(info, url):
    # TODO
    pass


class ImageProxy:

    def __init___(self):
        self.app = create_app()

    def response(self, flow: http.HTTPFlow) -> None:
        if 'content-type' in flow.response.headers:
            content_type = flow.response.headers['content-type']
            if content_type.startswith('image'):
                # check in database
                url = flow.request.pretty_url
                in_databse = Url.query.filter_by(value=url).first()
                if not in_databse:
                    ext = content_type.split('/')[1].split(';')[0]
                    invalid_exts = ['svg+xml', 'x-icon', 'gif']
                    if ext not in invalid_exts:
                        info = process_flow(flow, ext)
                        save_info(info, url)


addons = [
    ImageProxy()
]


if __name__ == '__main__':
    cli()
