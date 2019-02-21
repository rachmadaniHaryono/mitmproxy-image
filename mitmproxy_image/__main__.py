#!/usr/bin/env python
"""This script download all the image.

reference:
https://github.com/mitmproxy/mitmproxy/blob/master/examples/simple/internet_in_mirror.py
https://gist.github.com/denschub/2fcc4e03a11039616e5e6e599666f952
https://stackoverflow.com/a/44873382/1766261
"""
from datetime import datetime, date
from io import BytesIO
from json.decoder import JSONDecodeError
from logging.handlers import TimedRotatingFileHandler
from queue import Queue
import hashlib
import logging
import os
import pathlib  # require python 3.5+
import shutil
import tempfile
import time
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
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import OperationalError
from sqlalchemy.sql import func  # type: ignore  # NOQA
from sqlalchemy.types import TIMESTAMP
from sqlalchemy_utils.types import URLType
from flask import (
    abort,
    current_app,
    Flask,
    jsonify,
    request as flask_request,
    send_from_directory,
    url_for,
)
import click
import requests
import typing


APP_DIR = user_data_dir('mitmproxy_image', 'rachmadani haryono')
pathlib.Path(APP_DIR).mkdir(parents=True, exist_ok=True)
IMAGE_DIR = os.path.join(APP_DIR, 'image')
LOG_FILE = os.path.join(APP_DIR, 'mitmproxy_image.log')
SERVER_LOG_FILE = os.path.join(APP_DIR, 'mitmproxy_image_server.log')
DB_PATH = os.path.abspath(os.path.join(APP_DIR, 'mitmproxy_image.db'))
DB_URI = 'sqlite:///{}'.format(DB_PATH)


def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i + n]


def process_info(file_obj, ext=None, use_chunks=True, move_file=True):
    """Process info.

    Example using mitmproxy `flow`:
    >>> process_info(flow.response.content)  # doctest: +SKIP

    Use file object and move the file into `IMAGE_DIR` folder:
    >>> with open(image, 'rb') as f:  # doctest: +SKIP
    >>>     process_info(f, use_chunks=False)  # doctest: +SKIP

    To only calculate the file set `move_file` to `False`:
    >>> with open(image, 'rb') as f:  # doctest: +SKIP
    >>>     process_info(  # doctest: +SKIP
    >>>         f, use_chunks=False, move_file=False)   # doctest: +SKIP
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
            with open(temp_fname, 'wb', buffering=0) as f_temp:
                for b in file_iter:
                    h.update(b)
                    f_temp.write(b)
                    s.write(b)
                try:
                    img = Image.open(s)
                except OSError:
                    s.seek(0, os.SEEK_END)
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
        logging.error(traceback.format_exc())
        logging.error('{}:{}'.format(type(err), err))
        raise err
    return res


# MODEL
DB = SQLAlchemy()


class BaseModel(DB.Model):
    __abstract__ = True
    id = DB.Column(DB.Integer, primary_key=True)
    created_at = DB.Column(
        TIMESTAMP, default=datetime.now, nullable=False)


class Sha256Checksum(BaseModel):
    __tablename__ = 'sha256_checksum'
    value = DB.Column(DB.String, unique=True)
    ext = DB.Column(DB.String)
    filesize = DB.Column(DB.Integer)
    height = DB.Column(DB.Integer)
    width = DB.Column(DB.Integer)
    img_format = DB.Column(DB.String)
    img_mode = DB.Column(DB.String)
    urls = DB.relationship('Url', lazy='subquery', backref='checksum')
    trash = DB.Column(DB.Boolean, default=False)

    def __repr__(self):
        templ = "<Sha256Checksum(id={}, value={}...)>"
        return templ.format(self.id, self.value[:7])


class Url(BaseModel):
    __tablename__ = 'url'
    value = DB.Column(URLType, unique=True, nullable=False)
    sha256_checksum_id = DB.Column(
        DB.Integer, DB.ForeignKey('sha256_checksum.id'))
    redirect_counter = DB.Column(DB.Integer, default=0)
    check_counter = DB.Column(DB.Integer, default=0)
    last_redirect = DB.Column(
        DB.DateTime, server_default=func.now())
    last_check = DB.Column(
        DB.DateTime, server_default=func.now())

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
def create_app(script_info=None, db_uri=DB_URI):
    """create app.

    >>> app = create_app()
    """
    trf_hdlr = TimedRotatingFileHandler(SERVER_LOG_FILE, when='D', interval=30)
    app = Flask(__name__)
    app.logger.addHandler(trf_hdlr)
    app.config['SWAGGER'] = {
        'title': 'Mitmproxy Image',
        'uiversion': 2
    }
    swagger = Swagger(app)  # NOQA
    app.config['SECRET_KEY'] = os.urandom(24)
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    DB.init_app(app)
    app.app_context().push()

    @app.shell_context_processor
    def shell_context():
        return {
            'app': app, 'DB': DB,
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
    db_session = DB.session
    if flask_request.method == 'POST':
        url_value = flask_request.form.get('value', None)
    else:
        url_value = flask_request.args.get('value', None)
    if url_value is None:
        abort(404)
        return
    res = {}
    try:
        url_m = db_session.query(Url).filter_by(value=url_value).one_or_none()
        if url_m is None:
            abort(404)
            return
        res = {
            'id': url_m.id,
            'checksum_value': url_m.checksum.value,
            'checksum_trash': url_m.checksum.trash,
            'checksum_id': url_m.checksum.id,
            'img_url': url_for(
                '.image_url', _external=True, filename='{}.{}'.format(
                    url_m.checksum.value, url_m.checksum.ext)),
            'redirect_counter': url_m.redirect_counter,
            'check_counter': url_m.check_counter,
        }
        if flask_request.method == 'POST':
            redirect_counter = flask_request.form.get('redirect_counter', None)
            check_counter = flask_request.form.get('check_counter', None)
            if redirect_counter and redirect_counter == '+1':
                if url_m.redirect_counter is None:
                    url_m.redirect_counter = 1
                else:
                    url_m.redirect_counter += 1
            elif redirect_counter:
                current_app.logger.error('Unknown input:{}:{}'.format(
                    'redirect_counter', redirect_counter))
            if check_counter and check_counter == '+1':
                if url_m.check_counter is None:
                    url_m.check_counter = 1
                else:
                    url_m.check_counter += 1
            elif check_counter:
                current_app.logger.error('Unknown input:{}:{}'.format(
                    'check_counter', check_counter))
            db_session.add(url_m)
            db_session.commit()
            res['redirect_counter'] = url_m.redirect_counter
            res['check_counter'] = url_m.check_counter
    except OperationalError as err:
        logging.error(traceback.format_exc())
        logging.error('{}:{}\n{}:{}'.format(
            type(err), err, 'URL', url_value))
        res['error'] = str(err)
        db_session.rollback()
    finally:
        db_session.close()
    return jsonify(res)


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
    db_session = DB.session
    if flask_request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in flask_request.files:
            return jsonify({'error': 'No file part'})
        file_ = flask_request.files['file']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file_.filename == '':
            return jsonify({'error': 'No selected file'})
        with tempfile.NamedTemporaryFile(delete=False) as f_temp:
            file_.save(f_temp.name)
            url = flask_request.form.get('url', None)
            url_m = None
            try:
                if url is not None:
                    url_m, _ = get_or_create(db_session, Url, value=url)
                with open(f_temp.name, 'rb') as ff:
                    try:
                        info = process_info(ff, use_chunks=False)
                    except OSError as err:
                        logging.error(traceback.format_exc())
                        current_app.logger.error(
                            'URL FAILED:{}\nERROR:{}'.format(url, err))
                        abort(404)
                    with db_session.no_autoflush:
                        checksum_m, _ = get_or_create(
                            db_session, Sha256Checksum,
                            value=info.pop('value'))
                    for key, val in info.items():
                        setattr(checksum_m, key, val)
                    if url_m is not None:
                        checksum_m.urls.append(url_m)
                    db_session.add(checksum_m)
                    db_session.commit()
                    current_app.logger.debug(
                        'SERVER POST:\nurl: {}\nchecksum: {}'.format(
                            url_m.value, checksum_m.value)
                    )
            except OperationalError as err:
                db_session.rollback()
                current_app.logger.error('{}:{}'.format(
                    type(err), err))
                abort(500)
                return
            finally:
                db_session.remove()
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
    res = {}
    try:
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
        res = {
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
        }
    finally:
        db_session.remove()
    return jsonify(res)


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
    label = 'Getting all files'
    with click.progressbar(os.walk(IMAGE_DIR), label=label) as bar:
        for root, _, files in bar:
            for ff in files:
                im_data.append({
                    'basename': ff,
                    'value': os.path.splitext(os.path.basename(ff))[0],
                    'ext': os.path.splitext(ff)[1][1:],
                })
    db_session = DB.session

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
        label = 'Differentiate missing/existing items'
        with click.progressbar(im_data, label=label) as pg_im_data:
            for x in pg_im_data:
                (missing_items, existing_items)[
                    any(getattr(d, 'value') == x['value'] for d in db_items)
                ].append(x)
        if q_.count() != len(existing_items):
            # TODO set non non existing_items to trash
            raise NotImplementedError
        csm_ms = []
        if not missing_items:
            print('All item are on database.')
            return
        label = 'Processing missing items'
        with click.progressbar(missing_items, label=label) as pg_missing_items:
            for item in pg_missing_items:
                file_path = os.path.join(
                    IMAGE_DIR, item['value'][:2], item['basename'])
                with open(file_path, 'rb') as f:
                    info = process_info(f, use_chunks=False, move_file=False)
                    if info['value'] != item['value']:
                        # TODO move file
                        raise ValueError
                    checksum_m, _ = get_or_create(
                        db_session, Sha256Checksum,
                        value=info.pop('value'))
                    for key, val in info.items():
                        setattr(checksum_m, key, val)
                    checksum_m.trash = False
                    csm_ms.append(checksum_m)
        db_session.add_all(csm_ms)
        db_session.commit()


def store_flow_content(flow, redirect_host, redirect_port):
    """Store flow content by post it to server.

    >>> store_flow_content(flow, '127.0.0.1', 5012)  # doctest: +SKIP
    """
    # check url in database
    url = flow.request.pretty_url
    url_api_endpoint = 'http://{}:{}/api/url'.format(
        redirect_host, redirect_port)
    checksum_api_endpoint = 'http://{}:{}/api/sha256_checksum'.format(
        redirect_host, redirect_port)
    s = requests.Session()
    try:
        g_resp = s.get(url_api_endpoint, data={'value': url})
        if g_resp.status_code != 404:
            return
        with tempfile.NamedTemporaryFile(delete=False) as f:
            with open(f.name, 'wb') as ff:
                ff.write(flow.response.content)
            files = {'file': open(f.name, 'rb')}
            post_resp = s.post(
                checksum_api_endpoint, files=files, data={'url': url})
            if post_resp.status_code == 200:
                logging.info('URL DONE:{}'.format(flow.request.pretty_url))
    except Exception as err:
        logging.error('{}: {}'.format(type(err), err))
        logging.error(traceback.format_exc())
        raise err


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
    logging.basicConfig(filename=LOG_FILE, filemode='a', level=logging.DEBUG)
    logging.getLogger("hpack.hpack").setLevel(logging.INFO)
    logging.getLogger("hpack.table").setLevel(logging.INFO)
    logging.getLogger("PIL.PngImagePlugin").setLevel(logging.INFO)
    logging.getLogger("urllib3.connectionpool").setLevel(logging.INFO)


class MitmImage:

    def __init__(self):
        self.img_urls = []
        self.url_dict = {}
        self.highp_queue = Queue()
        self.mediump_queue = Queue()
        self.lowp_queue = Queue()

    def worker(self):
        while True:
            if not self.highp_queue.empty():
                c_queue = self.highp_queue
            elif not self.mediump_queue.empty():
                c_queue = self.mediump_queue
            elif not self.lowp_queue.empty():
                c_queue = self.lowp_queue
            else:
                break
            func_item = c_queue.get()
            try:
                func_item()
                time.sleep(5)
            except Exception as err:
                logging.error('{}: {}'.format(type(err), err))
                logging.error(traceback.format_exc())
            c_queue.task_done()

    def get_url_model(self, url):
        """Get url model and save it to self.url_dict."""
        redirect_host = ctx.options.redirect_host
        redirect_port = ctx.options.redirect_port
        url_api_endpoint = 'http://{}:{}/api/url'.format(
            redirect_host, redirect_port)
        if not redirect_host:
            return
        g_resp = requests.get(url_api_endpoint, params={'value': url})
        try:
            if g_resp.status_code in (404, 500):
                raise ValueError("status code error")
            json_resp = g_resp.json()
            self.url_dict[url] = json_resp
        except JSONDecodeError as err:
            logging.error('{}:{}\n{}:{}\n{}:{}\n{}:{}'.format(
                type(err), err,
                'URL', url,
                'status code', g_resp.status_code,
                'content', g_resp.content
            ))
            return
        except ValueError:
            logging.error('{}:{}:{}'.format(
                'STATUS CODE ERROR', g_resp.status_code, url))
            return

    def increase_counter(self, data_dict, log_header):
        """increate url model by send POST."""
        redirect_host = ctx.options.redirect_host
        redirect_port = ctx.options.redirect_port
        url_api_endpoint = 'http://{}:{}/api/url'.format(
            redirect_host, redirect_port)
        for key in data_dict:
            if key == 'value':
                url = data_dict[key]
            else:
                json_kw = key
        res = requests.post(url_api_endpoint, data=data_dict)
        if res.status_code == 200:
            json_res = res.json().get(json_kw, None)
            try:
                self.url_dict[url][json_kw] += 1
            except TypeError:
                self.url_dict[url][json_kw] = 1
        else:
            json_res = '?'
        logging.info('{}:{}:{}'.format(log_header, json_res, url))

    @concurrent
    def request(self, flow: http.HTTPFlow):
        redirect_host = ctx.options.redirect_host
        redirect_port = ctx.options.redirect_port
        if not redirect_host:
            return
        url = flow.request.pretty_url
        if url not in self.img_urls:
            logging.debug('NOT IN IMAGE LIST:{}'.format(url))
            return
        if redirect_host and \
                flow.request.host == redirect_host and \
                str(flow.request.port) == str(redirect_port):
            logging.info('SKIP REDIRECT SERVER: {}'.format(url))
            return
        if url in self.url_dict:
            json_resp = self.url_dict[url]
        else:
            self.mediump_queue.put(lambda: self.get_url_model(url))
            self.worker()
            return
        try:
            redirect_url = json_resp['img_url']
            checksum_trash = json_resp['checksum_trash']
            data_dict = {'value': url}
            json_kw = None
            log_header = None
            if not checksum_trash:
                if flow.request.http_version == 'HTTP/2.0':
                    flow.response = HTTPResponse(
                        'HTTP/1.1', 302, 'Found',
                        Headers(Location=redirect_url, Content_Length='0'),
                        b'')
                    logging.info('REDIRECT HTTP2: {}\nTO: {}'.format(
                        url, redirect_url))
                else:
                    flow.request.url = redirect_url
                    logging.info(
                        'REDIRECT: {}\nTO: {}'.format(url, redirect_url))
                json_kw = 'redirect_counter'
                log_header = 'REDIRECT COUNT'
            elif checksum_trash:
                logging.info(
                    'SKIP REDIRECT TRASH: {}'.format(flow.request.url))
                json_kw = 'check_counter'
                log_header = 'CHECK COUNT'
            else:
                logging.info(
                    '{}: url:{}, trash:{}'.format(
                        'Unknown condition', url, checksum_trash))
            if json_kw:
                data_dict[json_kw] = '+1'
                self.lowp_queue.put(
                    lambda: self.increase_counter(data_dict, log_header))
        except Exception as err:
            logging.error('{}: {}'.format(type(err), err))
            logging.error(traceback.format_exc())

    @concurrent
    def response(self, flow: http.HTTPFlow) -> None:
        """Handle response."""
        redirect_host = ctx.options.redirect_host
        redirect_port = ctx.options.redirect_port
        url = flow.request.pretty_url
        if not redirect_host:
            logging.debug('No redirect host.\nUrl: {}'.format(url))
        if redirect_host and \
                flow.request.host == redirect_host and \
                str(flow.request.port) == str(redirect_port):
            logging.info('SKIP REDIRECT SERVER: {}'.format(url))
            return
        if 'content-type' in flow.response.headers:
            content_type = flow.response.headers['content-type']
            ext = content_type.split('/')[1].split(';')[0]
            invalid_exts = [
                'svg+xml', 'x-icon', 'gif',
                'vnd.microsoft.icon', 'webp']
            if content_type.startswith('image') and ext not in invalid_exts:
                if url not in self.img_urls:
                    self.img_urls.append(url)
                self.highp_queue.put(
                    lambda: store_flow_content(
                        flow, redirect_host, redirect_port))
                self.worker()
                return


addons = [
    MitmImage()
]


if __name__ == '__main__':
    cli()
