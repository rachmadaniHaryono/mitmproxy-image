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
from mitmproxy import ctx, http
from PIL import Image
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, relationship, scoped_session, sessionmaker
from sqlalchemy.types import TIMESTAMP
from sqlalchemy_utils.types import URLType
import click
import sqlalchemy


APP_DIR = click.get_app_dir('mitmproxy_image')
pathlib.Path(APP_DIR).mkdir(parents=True, exist_ok=True)
IMAGE_DIR = os.path.join(APP_DIR, 'image')


def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i + n]


def process_info(file_obj, ext, use_chunks=True):
    folder = IMAGE_DIR
    h = hashlib.sha256()
    block = 128*1024
    s = BytesIO()
    res = {}
    if use_chunks:
        file_iter = chunks(file_obj, block)
    else:
        file_iter = iter(lambda: file_obj.read(block), b'')
    try:
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_fname = f.name
            with open(temp_fname, 'wb', buffering=0) as f:
                for b in file_iter:
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
        ctx.log.error('{}:{}'.format(type(e), e))
    return res


def get_database_uri():
    abspath = os.path.abspath(os.path.join(APP_DIR, 'mitmproxy_image.db'))
    return 'sqlite:///{}'.format(abspath)


# MODEL
Base = declarative_base()


class BaseModel(Base):
    __abstract__ = True
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
    created_at = sqlalchemy.Column(
        TIMESTAMP, default=datetime.now, nullable=False)


class Sha256Checksum(BaseModel):
    __tablename__ = 'sha256_checksum'
    value = sqlalchemy.Column(sqlalchemy.String, unique=True)
    ext = sqlalchemy.Column(sqlalchemy.String)
    filesize = sqlalchemy.Column(sqlalchemy.Integer)
    height = sqlalchemy.Column(sqlalchemy.Integer)
    width = sqlalchemy.Column(sqlalchemy.Integer)
    img_format = sqlalchemy.Column(sqlalchemy.String)
    img_mode = sqlalchemy.Column(sqlalchemy.String)
    urls = relationship('Url', lazy='subquery', backref='checksum')
    trash = sqlalchemy.Column(sqlalchemy.Boolean, default=False)

    def __repr__(self):
        templ = "<Sha256Checksum(id={}, value={}...)>"
        return templ.format(self.id, self.value[:7])


class Url(BaseModel):
    __tablename__ = 'url'
    value = sqlalchemy.Column(URLType, unique=True, nullable=False)
    sha256_checksum_id = sqlalchemy.Column(
        sqlalchemy.Integer, sqlalchemy.ForeignKey('sha256_checksum.id'))


def get_or_create(session, model, **kwargs):
    """Creates an object or returns the object if exists."""
    instance = session.query(model).filter_by(**kwargs).first()
    created = False
    if not instance:
        instance = model(**kwargs)
        session.add(instance)
        created = True
    return instance, created


# FLASK
def create_app(script_info=None):
    """create app."""
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.urandom(24)
    app.config['WTF_CSRF_ENABLED'] = False

    # app and db
    #  db.init_app(app)
    app.app_context().push()
    #  db.create_all()

    db_uri = get_database_uri()
    #  print('db uri: {}'.format(db_uri))
    engine = sqlalchemy.create_engine(db_uri)
    db_session = scoped_session(sessionmaker(bind=engine))

    @app.teardown_appcontext
    def shutdown_session(exception=None):
        db_session.remove()

    @app.shell_context_processor
    def shell_context():
        return {
            'app': app,
            'db_session': db_session,
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


class ImageProxy:

    def response(self, flow: http.HTTPFlow) -> None:
        if 'content-type' in flow.response.headers:
            content_type = flow.response.headers['content-type']
            if content_type.startswith('image'):
                # session
                db_uri = get_database_uri()
                engine = sqlalchemy.create_engine(db_uri)
                Base.metadata.create_all(engine)
                session = Session(engine)

                # check in database
                url = flow.request.pretty_url
                in_database = \
                    session.query(Url).filter_by(value=url).first()
                if not in_database:
                    ext = content_type.split('/')[1].split(';')[0]
                    invalid_exts = ['svg+xml', 'x-icon', 'gif']
                    if ext not in invalid_exts:
                        info = process_info(flow.response.content, ext)
                        url_m, _ = get_or_create(session, Url, value=url)
                        with session.no_autoflush:
                            checksum_m, _ = get_or_create(
                                session, Sha256Checksum,
                                value=info.pop('value'))
                        for key, val in info.items():
                            setattr(checksum_m, key, val)
                        checksum_m.urls.append(url_m)
                        session.add(checksum_m)
                        session.commit()
                else:
                    ctx.log.info('SKIP: {}'.format(url))


addons = [
    ImageProxy()
]


if __name__ == '__main__':
    cli()
