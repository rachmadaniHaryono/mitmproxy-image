#!/usr/bin/env python
"""This script download all the image.

reference:
https://github.com/mitmproxy/mitmproxy/blob/master/examples/simple/internet_in_mirror.py
https://gist.github.com/denschub/2fcc4e03a11039616e5e6e599666f952
https://stackoverflow.com/a/44873382/1766261
"""
from datetime import datetime, date
from io import BytesIO
from urllib.parse import ParseResult
import hashlib
import logging
import os
import pathlib  # require python 3.5+
import shutil
import tempfile
import traceback
import sys

from appdirs import user_data_dir
from flasgger import Swagger
from flask.cli import FlaskGroup
from flask_admin import Admin, AdminIndexView
from mitmproxy import ctx, http
from mitmproxy.http import HTTPResponse
from mitmproxy.net.http.headers import Headers
from mitmproxy.script import concurrent
from PIL import Image
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, scoped_session, sessionmaker
from sqlalchemy.sql import func  # type: ignore  # NOQA
from sqlalchemy.types import TIMESTAMP
from sqlalchemy_utils.types import URLType
from flask import (
    abort,
    Flask,
    jsonify,
    request as flask_request,
    send_from_directory,
    url_for,
)
import click
import requests
import sqlalchemy
import typing


APP_DIR = user_data_dir('mitmproxy_image', 'rachmadani haryono')
pathlib.Path(APP_DIR).mkdir(parents=True, exist_ok=True)
IMAGE_DIR = os.path.join(APP_DIR, 'image')
LOG_FILE = os.path.join(APP_DIR, 'mitmproxy_image.log')
logging.basicConfig(filename=LOG_FILE, filemode='a', level=logging.DEBUG)
logging.getLogger("hpack.hpack").setLevel(logging.INFO)
logging.getLogger("hpack.table").setLevel(logging.INFO)
logging.getLogger("PIL.PngImagePlugin").setLevel(logging.INFO)


def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i + n]


def process_info(file_obj, ext=None, use_chunks=True, move_file=True):
    """Process info.

    >>> # example using mitmproxy `flow`
    >>> process_info(flow.response.content)
    {...}
    >>> # use file object and move the file into `IMAGE_DIR` folder
    >>> with open(image, 'rb') as f:
    >>>     process_info(f, use_chunks=False)
    {...}
    >>> # to only calculate the file set `move_file` to `False`
    >>> with open(image, 'rb') as f:
    >>>     process_info(f, use_chunks=False, move_file=False)
    {...}
    """
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
            if not ext:
                ext = img.format.lower()
            if move_file:
                new_bname = '{}.{}'.format(sha256_csum, ext)
                parent_folder = os.path.join(folder, sha256_csum[:2])
                new_fname = os.path.join(parent_folder, new_bname)
                pathlib.Path(parent_folder).mkdir(parents=True, exist_ok=True)
                shutil.move(temp_fname, new_fname)
                logging.info('DONE:{}'.format(new_fname))
            else:
                logging.info('ANALYZED:{}'.format(sha256_csum))
        res = {
            'value': sha256_csum,
            'filesize': filesize,
            'ext': ext,
            'width': img.size[0],
            'height': img.size[1],
            'img_format': img.format,
            'img_mode': img.mode
        }
    except Exception as err:
        logging.error('{}:{}'.format(type(err), err))
        raise err
    return res


def get_database_uri():
    abspath = os.path.abspath(os.path.join(APP_DIR, 'mitmproxy_image.db'))
    return 'sqlite:///{}'.format(abspath)


def get_db_session(connect_args=None):
    db_uri = get_database_uri()
    if not connect_args:
        engine = sqlalchemy.create_engine(db_uri)
    else:
        engine = sqlalchemy.create_engine(db_uri, connect_args=connect_args)
    return scoped_session(sessionmaker(bind=engine))


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
    redirect_counter = sqlalchemy.Column(sqlalchemy.Integer, default=0)
    check_counter = sqlalchemy.Column(sqlalchemy.Integer, default=0)
    last_redirect = sqlalchemy.Column(
        sqlalchemy.DateTime, server_default=func.now())
    last_check = sqlalchemy.Column(
        sqlalchemy.DateTime, server_default=func.now())

    def __repr__(self):
        templ = "<Url(id={}, value={}, checksum={})>"
        return templ.format(self.id, self.value, self.checksum)


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

    db_session = get_db_session()

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
        '/api/sha256_checksum', 'sha256_checksum_list',
        sha256_checksum_list, methods=['GET', 'POST'])
    app.add_url_rule(
        '/api/url', 'url_list',
        url_list, methods=['GET', 'POST'])
    app.add_url_rule('/i/<path:filename>', 'image_url', image_url)

    Admin(
        app, name='Mitmproxy-Image', template_mode='bootstrap3',
        index_view=AdminIndexView(name='Home', url='/')
    )
    return app


def url_list():
    db_session = get_db_session()
    url_value = flask_request.args.get('value', None)
    if url_value is None:
        abort(404)
        return
    url_m = db_session.query(Url).filter_by(value=url_value).one_or_none()
    if url_m is None:
        abort(404)
        return
    return jsonify({
        'id': url_m.id,
        'checksum_value': url_m.checksum.value,
        'checksum_trash': url_m.checksum.trash,
        'checksum_id': url_m.checksum.id,
        'img_url': url_for(
            '.image_url', _external=True,
            filename='{}.{}'.format(url_m.checksum.value, url_m.checksum.ext)),
    })


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
    db_session = get_db_session()
    if flask_request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in flask_request.files:
            return jsonify({'error': 'No file part'})
        file_ = flask_request.files['file']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file_.filename == '':
            return jsonify({'error': 'No selected file'})
        with tempfile.NamedTemporaryFile(delete=False) as f:
            file_.save(f.name)
            url = flask_request.form.get('url', None)
            url_m = None
            if url is not None:
                url_m, _ = get_or_create(db_session, Url, value=url)
            with open(f.name, 'rb') as f:
                info = process_info(f, use_chunks=False)
                with db_session.no_autoflush:
                    checksum_m, _ = get_or_create(
                        db_session, Sha256Checksum,
                        value=info.pop('value'))
                for key, val in info.items():
                    setattr(checksum_m, key, val)
                if url_m is not None:
                    checksum_m.urls.append(url_m)
                db_session.add(checksum_m)
                logging.debug('SERVER POST:\nurl: {}\nchecksum: {}'.format(
                    url_m.value, checksum_m.value
                ))
                db_session.commit()
        return jsonify({'status': 'success'})
    input_query = flask_request.args.get('q')
    qs_dict = {}
    if input_query is not None:
        for item in input_query.split():
            if ':' not in item:
                continue
            parts = item.split(':', 1)
            qs_dict[parts[0]] = parts[1]
    #  initial value
    per_page = 200
    created_at = None
    # per_page
    per_page = int(os.environ.get('MITMPROXY_IMAGE_PER_PAGE', per_page))
    per_page = int(flask_request.args.get('per_page', per_page))
    per_page = int(qs_dict.get('per_page', per_page))
    # created_at
    created_at = flask_request.args.get('created_at', created_at)
    created_at = qs_dict.get('created_at', created_at)
    # other args
    page = int(flask_request.args.get('page', 1))
    dsq = db_session.query(Sha256Checksum) \
        .filter_by(trash=False) \
        .order_by(Sha256Checksum.created_at.desc())
    if created_at is not None and created_at == 'today':
        dsq = dsq.filter(
            func.DATE(Sha256Checksum.created_at) == date.today()
        )
    if per_page > 0:
        dsq = dsq.limit(per_page).offset((int(page) - 1) * per_page)
    items = dsq.all()
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
    im_data = []
    with click.progressbar(os.walk(IMAGE_DIR)) as bar:
        for root, _, files in bar:
            for ff in files:
                im_data.append({
                    'basename': ff,
                    'value': os.path.splitext(os.path.basename(ff))[0],
                    'ext': os.path.splitext(ff)[1][1:],
                })
    db_session = get_db_session()

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
        print(
            '[non trash]before:{}, after:{}'.format(
                non_trash_count,
                db_session.query(Sha256Checksum)
                .filter_by(trash=False).count()))
        db_session.commit()
    else:
        existing_items, missing_items = [], []
        q_ = db_session.query(Sha256Checksum).filter_by(trash=False)
        db_items = q_.all()
        with click.progressbar(im_data) as pg_im_data:
            for x in pg_im_data:
                (missing_items, existing_items)[
                    any(getattr(d, 'value') == x['value'] for d in db_items)
                ].append(x)
        if q_.count() != len(existing_items):
            # TODO set non non existing_items to trash
            raise NotImplementedError
        with click.progressbar(missing_items) as pg_missing_items:
            for item in pg_missing_items:
                file_path = os.path.join(
                    IMAGE_DIR, item['value'][:2], item['basename'])
                with open(file_path, 'rb') as f:
                    info = process_info(f, use_chunks=False, move_file=False)
                    if info['value'] != item['value']:
                        # TODO move file
                        raise ValueError
                    with db_session.no_autoflush:
                        checksum_m, _ = get_or_create(
                            db_session, Sha256Checksum,
                            value=info.pop('value'))
                    for key, val in info.items():
                        setattr(checksum_m, key, val)
                    db_session.add(checksum_m)
                    db_session.commit()


def store_flow_content(flow, redirect_host, redirect_port):
    # check in database
    url = flow.request.pretty_url

    url_api_endpoint = 'http://{}:{}/api/url'.format(
        redirect_host, redirect_port)
    checksum_api_endpoint = 'http://{}:{}/api/sha256_checksum'.format(
        redirect_host, redirect_port)
    g_resp = requests.get(url_api_endpoint, data={'value': url})
    if g_resp.status_code == 404:
        with tempfile.NamedTemporaryFile(delete=False) as f:
            with open(f.name, 'wb') as ff:
                ff.write(flow.response.content)
            files = {'file': open(f.name, 'rb')}
            r = requests.post(
                checksum_api_endpoint, files=files, data={'url': url})
            logging.debug('CLIENT POST: {}'.format(r.status_code))


def load(loader):
    loader.add_option(
        name="redirect_host",
        typespec=typing.Optional[str],
        default=None,
        help="Server host for redirect.",
    )
    loader.add_option(
        name="redirect_port",
        typespec=typing.Optional[int],
        default=None,
        help="Server port for redirect.",
    )


mitm_db_session = get_db_session({'check_same_thread': False})


@concurrent
def request(flow: http.HTTPFlow):
    redirect_host = ctx.options.redirect_host
    redirect_port = ctx.options.redirect_port
    if not redirect_host:
        return
    # db session
    Base.metadata.create_all(sqlalchemy.create_engine(get_database_uri()))
    db_session = mitm_db_session

    try:
        url = flow.request.pretty_url
        url_m = db_session.query(Url).filter_by(value=url).first()
        redirect_netloc = \
            redirect_host if not redirect_port else \
            '{}:{}'.format(redirect_host, redirect_port)
        redirect_url = ParseResult(
            scheme='http', netloc=redirect_netloc,
            path='i/{}.{}'.format(
                url_m.checksum.value, url_m.checksum.ext) if url_m else '',
            params='', query='', fragment=''
        ).geturl()
        if url_m and url_m.redirect_counter is None:
            url_m.redirect_counter = 0
        if url_m and url_m.check_counter is None:
            url_m.check_counter = 0
        if not url_m:
            pass
        elif url_m and not url_m.checksum.trash and \
                flow.request.http_version == 'HTTP/2.0':
            flow.response = HTTPResponse(
                'HTTP/1.1', 302, 'Found',
                Headers(Location=redirect_url, Content_Length='0'),
                b'')
            logging.info('REDIRECT HTTP2: {}\nTO: {}'.format(
                url, redirect_url))
            url_m.redirect_counter += 1
            url_m.last_redirect = datetime.now()
            logging.info('REDIRECT COUNT: {}'.format(url_m.redirect_counter))
        elif url_m and url_m.checksum.trash:
            logging.info('SKIP REDIRECT TRASH: {}'.format(
                flow.request.url))
            url_m.check_counter += 1
            url_m.last_check = datetime.now()
            logging.info('CHECK COUNT: {}'.format(url_m.check_counter))
        elif url_m and not url_m.checksum.trash:
            flow.request.url = redirect_url
            logging.info('REDIRECT: {}\nTO: {}'.format(
                url, redirect_url))
            url_m.redirect_counter += 1
            url_m.last_redirect = datetime.now()
            logging.info('REDIRECT COUNT: {}'.format(url_m.redirect_counter))
        else:
            logging.info(
                'Unknown condition: url:{}, trash:{}'.format(
                    url_m, url_m.checksum.trash if url_m else None))
        if url_m:
            db_session.add(url_m)
            db_session.commit()
    except Exception as err:
        logging.error('{}: {}'.format(type(err), err))
        logging.error(traceback.format_exc())


@concurrent
def response(flow: http.HTTPFlow) -> None:
    """Handle response."""
    redirect_host = ctx.options.redirect_host
    redirect_port = ctx.options.redirect_port
    if redirect_host and \
            flow.request.host == redirect_host and \
            str(flow.request.port) == str(redirect_port):
        url = flow.request.pretty_url
        logging.info('SKIP REDIRECT SERVER: {}'.format(url))
        return
    if 'content-type' in flow.response.headers:
        content_type = flow.response.headers['content-type']
        ext = content_type.split('/')[1].split(';')[0]
        invalid_exts = [
            'svg+xml', 'x-icon', 'gif',
            'vnd.microsoft.icon', 'webp']
        if content_type.startswith('image') and ext not in invalid_exts:
            try:
                if redirect_host:
                    store_flow_content(
                        flow, redirect_host, redirect_port)
                else:
                    db_session = mitm_db_session
                    # check in database
                    url = flow.request.pretty_url
                    url_m = \
                        db_session.query(Url).filter_by(value=url).first()
                    if not url_m:
                        logging.info('URL: {}'.format(url))
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
                    elif url_m and url_m.checksum.trash and not redirect_host:
                        logging.info('SKIP TRASH: {}'.format(url))
            except Exception as err:
                logging.error('{}: {}'.format(type(err), err))
                logging.error(traceback.format_exc())
                raise err


if __name__ == '__main__':
    cli()
