#!/usr/bin/env python
"""This script download all the image.

reference:
https://github.com/mitmproxy/mitmproxy/blob/master/examples/simple/internet_in_mirror.py
https://gist.github.com/denschub/2fcc4e03a11039616e5e6e599666f952
https://stackoverflow.com/a/44873382/1766261
"""
from datetime import datetime
from io import BytesIO
from urllib.parse import ParseResult
import hashlib
import logging
import os
import pathlib  # require python 3.5+
import shutil
import tempfile
import sys

from appdirs import user_data_dir
from flask import Flask, send_from_directory, url_for, jsonify, request
from flask.cli import FlaskGroup
from flasgger import Swagger
from mitmproxy import ctx, http
from PIL import Image
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, scoped_session, sessionmaker
from sqlalchemy.types import TIMESTAMP
from sqlalchemy_utils.types import URLType
import click
import sqlalchemy
import typing


APP_DIR = user_data_dir('mitmproxy_image', 'rachmadani haryono')
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
        if hasattr(ctx.log, 'info'):
            ctx.log.info('DONE:{}'.format(new_fname))
        else:
            print('DONE:{}'.format(new_fname))
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
        if hasattr(ctx.log, 'error'):
            ctx.log.error('{}:{}'.format(type(e), e))
        else:
            raise e
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
    app.config['SWAGGER'] = {
        'title': 'Mitmproxy Image',
        'uiversion': 2
    }
    swagger = Swagger(app)  # NOQA
    app.config['SECRET_KEY'] = os.urandom(24)
    app.config['WTF_CSRF_ENABLED'] = False

    # app and db
    #  db.init_app(app)
    app.app_context().push()
    #  db.create_all()

    db_uri = get_database_uri()
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

    app.add_url_rule(
        '/api/sha256_checksum', 'sha256_checksum_list', sha256_checksum_list)
    app.add_url_rule('/i/<path:filename>', 'image_url', image_url)
    return app


def sha256_checksum_list():
    """Example endpoint returning a list of checksum by palette
    ---
    parameters:
      - name: page
        in: query
        type: integer
    responses:
      200:
        description: A list of sha256 checksum
    """
    db_uri = get_database_uri()
    engine = sqlalchemy.create_engine(db_uri)
    db_session = scoped_session(sessionmaker(bind=engine))
    per_page = int(os.environ.get('MITMPROXY_IMAGE_PER_PAGE', 200))
    page = int(request.args.get('page', 1))
    input_query = request.args.get('q')
    items = db_session.query(Sha256Checksum) \
        .filter_by(trash=False) \
        .order_by(Sha256Checksum.created_at.desc()) \
        .limit(per_page).offset((int(page) - 1) * per_page).all()
    return jsonify({
        'items': [{
            'created_at': str(item.created_at),
            'value': str(item.value),
            'urls': [url.value for url in item.urls],
            'img_url': url_for(
                '.image_url', _external=True,
                filename='{}.{}'.format(item.value, item.ext)),
        } for item in items],
        'next_page': url_for(
            'sha256_checksum_list', page=page+1, q=input_query,
            _external=True)
    })


def image_url(filename):
    return send_from_directory(
        IMAGE_DIR, os.path.join(filename[:2], filename))


@click.group(cls=FlaskGroup, create_app=create_app)
def cli():
    """This is a script for application."""
    pass


@cli.command('echo-path')
def echo_path():
    'Echo path to script.'
    print(__file__)


@cli.command('scan-image-folder')
def scan_image_folder():
    """Scan image folder.

    This function find problems in image folder.
    - empty filesize (trash)
    - empty ext (process info, save if image)
    - file not in database (process info, save  if image)
    - file in database but not in image folder (set trash prop = True)
    - file in db and folder, trash prop=true (set trash prop = False)
    - file in database but empty filesize (trash)
    """
    logging.basicConfig(level=logging.INFO, stream=sys.stdout)
    im_data = {}
    with click.progressbar(os.walk(IMAGE_DIR)) as bar:
        for root, _, files in bar:
            for ff in files:
                im_data[ff] = {
                    'exp_value': os.path.splitext(os.path.basename(ff))[0],
                    'ext': os.path.splitext(ff)[1][1:],
                }
    db_uri = get_database_uri()
    engine = sqlalchemy.create_engine(db_uri)
    db_session = scoped_session(sessionmaker(bind=engine))

    if not im_data:
        mappings = []
        i = 0
        q_ = db_session.query(Sha256Checksum).filter_by(trash=False)
        non_trash_count = q_.count()
        for m in q_.all():
            info = {'id': m.id, 'trash': True}
            mappings.append(info)
            i = i + 1
            if i % 10000 == 0:
                db_session.bulk_update_mappings(Sha256Checksum, mappings)
                db_session.flush()
                db_session.commit()
                mappings[:] = []
        db_session.bulk_update_mappings(Sha256Checksum, mappings)
        logging.info(
            '[non trash]before:{}, after:{}'.format(
                non_trash_count,
                db_session.query(Sha256Checksum)
                .filter_by(trash=False).count()))
        db_session.commit()
    else:
        #  TODO
        raise NotImplementedError


class ImageProxy:

    def load(self, loader):
        loader.add_option(
            name="redirect_netloc",
            typespec=typing.Optional[str],
            default=None,
            help="Server netloc for redirect.",
        )

    def response(self, flow: http.HTTPFlow) -> None:
        """Handle response."""
        if 'content-type' in flow.response.headers:
            content_type = flow.response.headers['content-type']
            if content_type.startswith('image'):
                # session
                db_uri = get_database_uri()
                engine = sqlalchemy.create_engine(db_uri)
                Base.metadata.create_all(engine)
                db_session = scoped_session(sessionmaker(bind=engine))

                redirect_netloc = ctx.options.redirect_netloc
                try:
                    # check in database
                    url = flow.request.pretty_url
                    in_database = \
                        db_session.query(Url).filter_by(value=url).first()
                    url_m = in_database
                    if not in_database:
                        ext = content_type.split('/')[1].split(';')[0]
                        invalid_exts = [
                            'svg+xml', 'x-icon', 'gif',
                            'vnd.microsoft.icon', 'webp']
                        if ext not in invalid_exts:
                            info = process_info(flow.response.content, ext)
                            url_m, _ = get_or_create(
                                db_session, Url, value=url)
                            with db_session.no_autoflush:
                                checksum_m, _ = get_or_create(
                                    db_session, Sha256Checksum,
                                    value=info.pop('value'))
                            for key, val in info.items():
                                setattr(checksum_m, key, val)
                            checksum_m.urls.append(url_m)
                            db_session.add(checksum_m)
                            db_session.commit()
                    elif not url_m.checksum.trash and redirect_netloc:
                        redirect_url = ParseResult(
                            scheme='http', netloc=redirect_netloc,
                            path='i/{}.{}'.format(
                                url_m.checksum.value, url_m.checksum.ext),
                            params='', query='', fragment=''
                        ).geturl()
                        flow.request.url = redirect_url
                        ctx.log.info('REDIRECT: {}\nTO: {}'.format(
                            url, redirect_url))
                    else:
                        ctx.log.info('SKIP: {}'.format(url))
                finally:
                    db_session.remove()


addons = [
    ImageProxy()
]


if __name__ == '__main__':
    cli()
