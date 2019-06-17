#!/usr/bin/env python
"""This script download all the image.

reference:
https://github.com/mitmproxy/mitmproxy/blob/master/examples/simple/internet_in_mirror.py
https://gist.github.com/denschub/2fcc4e03a11039616e5e6e599666f952
https://stackoverflow.com/a/44873382/1766261
"""
from datetime import datetime, date
import logging
import os
import pathlib
import shutil
import tempfile
import traceback
import sys
import shlex
from typing import Any, Optional, Union, Tuple, TypeVar

from appdirs import user_data_dir
from flasgger import Swagger
from flask.cli import FlaskGroup
from flask.views import MethodView
from flask_admin import Admin, AdminIndexView
from flask_sqlalchemy import SQLAlchemy
from hashfile import hash_file
from mitmproxy import ctx, http, command
from mitmproxy.http import HTTPResponse
from mitmproxy.net.http.headers import Headers
from mitmproxy.script import concurrent
from mitmproxy.tools._main import mitmproxy
from PIL import Image
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm.exc import DetachedInstanceError
from sqlalchemy.orm.scoping import scoped_session
from sqlalchemy.sql import func  # type: ignore  # NOQA
from sqlalchemy.types import TIMESTAMP
from sqlalchemy_utils import database_exists
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
LOG_FORMAT = '%(asctime)s %(levelname)s - %(message)s'
FORMATTER = logging.Formatter(LOG_FORMAT)
# db
DB_PATH = os.path.abspath(os.path.join(APP_DIR, 'mitmproxy_image.db'))
DB_URI = 'sqlite:///{}'.format(DB_PATH)
DB = SQLAlchemy()
# annotation
Sha256ChecksumVar = TypeVar('Sha256ChecksumVar', bound='Sha256Checksum')
UrlVar = TypeVar('UrlVar', bound='Url')


# MODEL

class BaseModel(DB.Model):  # type: ignore
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

    def to_dict(self, include_urls=True):
        res = {}
        keys = [
            'value', 'ext', 'filesize', 'height', 'width', 'img_format',
            'img_mode', 'trash']
        if include_urls:
            keys.append('urls')
        for k in keys:
            if k == 'urls':
                res[k] = [x.to_dict(
                    include_checksum=False) for x in getattr(self, k, [])]
            else:
                res[k] = getattr(self, k)
        return res

    @staticmethod
    def get_or_create(
            filepath: str,
            url: Optional[Union[str, UrlVar]] = None,
            session: Optional[scoped_session] = None,
            image_dir: Union[str, 'os.PathLike[str]'] = IMAGE_DIR
    ) -> Tuple[Sha256ChecksumVar, bool]:
        hash_value = hash_file(filepath, 'sha256')
        instance, created = get_or_create(
            session, Sha256Checksum, value=hash_value)
        if url and isinstance(url, str):
            url_m = get_or_create(session, Url, value=url)[0]
            instance.urls.append(url_m)
        elif url and isinstance(url, Url):
            url_m = url
            instance.urls.append(url_m)
        if created:
            instance.filesize = os.path.getsize(filepath)
            pil_img = Image.open(filepath)
            instance.ext = pil_img.format.lower()
            instance.width, instance.height = pil_img.size
            instance.img_format = pil_img.format
            instance.img_mode = pil_img.mode
            instance.trash = False
        if not instance.trash:
            new_filepath = os.path.join(
                image_dir, hash_value[:2],
                hash_value + '.{}'.format(instance.ext))
            pathlib.Path(os.path.dirname(
                new_filepath)).mkdir(parents=True, exist_ok=True)
            if filepath != new_filepath:
                shutil.copyfile(filepath, new_filepath)
            else:
                logging.debug('Same file: {}'.format(filepath))
        return instance, created


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

    def to_dict(self, include_checksum=True):
        res = {}
        keys = [
            'id', 'value', 'redirect_counter',  'check_counter',
            'last_redirect', 'last_check']
        if include_checksum:
            keys.append('checksum')
        for k in keys:
            if k == 'checksum' and self.checksum:
                res[k] = self.checksum.to_dict(include_urls=False)
            if k == 'checksum':
                pass
            else:
                res[k] = str(getattr(self, k))
        if self.checksum:
            try:
                img_url = url_for(
                    '.image_url', _external=True, filename='{}.{}'.format(
                        self.checksum.value, self.checksum.ext)),
                res['img_url'] = img_url
            except RuntimeError as err:
                logging.warning('{}:{}'.format(type(err), err))
        return res

    @staticmethod
    def get_or_create(
            value: str,
            session: Optional[scoped_session] = DB.session
    ) -> Tuple[UrlVar, bool]:
        instance, created = get_or_create(session, Url, value=value)
        return instance, created


def get_or_create(
        session: scoped_session,
        model: Any,
        **kwargs
) -> Tuple[Any, bool]:
    """Creates an object or returns the object if exists."""
    instance = session.query(model).filter_by(**kwargs).first()
    created = False
    if not instance:
        instance = model(**kwargs)
        session.add(instance)
        created = True
    return instance, created


# FLASK
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
    swagger = Swagger(app)  # NOQA
    app.config['SECRET_KEY'] = os.urandom(24)
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    if debug:
        app.config['DEBUG'] = debug
    if testing:
        app.config['TESTING'] = testing

    DB.init_app(app)
    app.app_context().push()
    if \
            not database_exists(db_uri) or \
            not DB.engine.dialect.has_table(DB.engine, 'url'):
        DB.create_all()
        logging.debug('database created')

    @app.shell_context_processor
    def shell_context():
        return {
            'app': app, 'DB': DB,
            'Sha256Checksum': Sha256Checksum, 'Url': Url,
        }

    # route
    sha256_checksum_view = Sha256ChecksumView.as_view('sha256_checksum')
    app.add_url_rule(
        '/api/sha256_checksum',
        view_func=sha256_checksum_view,
        methods=['GET', 'POST'])
    url_view = UrlView.as_view('url_view')
    app.add_url_rule(
        '/api/url',
        view_func=url_view,
        methods=['GET', 'POST'])
    app.add_url_rule('/i/<path:filename>', 'image_url', image_url)

    def test():
        app.logger.debug('test page')
        return 'hello world'
    app.add_url_rule('/test', 'test', test)

    Admin(
        app, name='Mitmproxy-Image', template_mode='bootstrap3',
        index_view=AdminIndexView(name='Home', url='/')
    )
    return app


class Sha256ChecksumView(MethodView):

    def get(self):
        db_session = DB.session
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
                    'sha256_checksum', page=page+1, q=input_query,
                    _external=True)
            }
        finally:
            db_session.remove()
        return jsonify(res)

    def post(self):
        db_session = DB.session
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
                # TODO
                raise NotImplementedError
                with db_session.no_autoflush:
                    checksum_m = Sha256Checksum.get_or_create(
                        f_temp.name, session=db_session)[0]
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
                current_app.logger.error(traceback.format_exc())
                current_app.logger.error('{}:{}'.format(
                    type(err), err))
                abort(500)
                return
            finally:
                db_session.remove()
        return jsonify({'status': 'success'})


class UrlView(MethodView):

    def get(self):
        db_session = DB.session
        url_value = flask_request.args.get('value', None)
        if url_value is None:
            return jsonify([x.to_dict() for x in db_session.query(Url).all()])
        res = {}
        try:
            url_m = \
                db_session.query(Url).filter_by(value=url_value).one_or_none()
            if url_m is None:
                abort(404)
                return
            res = url_m.to_dict()
            if url_m.checksum:
                res['checksum_value'] = url_m.checksum_value
                res['checksum_trash'] = url_m.checksum_trash
            if flask_request.method == 'POST':
                for key in ('redirect_counter''check_counter'):
                    var = flask_request.form.get(key, None)
                    if var and var == '+1':
                        if getattr(url_m, key, None) is None:
                            setattr(url_m, key)
                        else:
                            setattr(url_m, key, getattr(url_m, key) + 1)
                    elif var:
                        current_app.logger.error('Unknown input:{}:{}'.format(
                            key, var))
                db_session.add(url_m)
                db_session.commit()
                res['redirect_counter'] = url_m.redirect_counter
                res['check_counter'] = url_m.check_counter
        except OperationalError as err:
            current_app.logger.error(traceback.format_exc())
            current_app.logger.error('{}:{}\n{}:{}'.format(
                type(err), err, 'URL', url_value))
            res['error'] = str(err)
            db_session.rollback()
        finally:
            db_session.close()
        return jsonify(res)

    def post(self):
        db_session = DB.session
        url_value = flask_request.form.get('value', None)
        if url_value is None:
            abort(404)
            return
        res = {}
        try:
            url_m = \
                db_session.query(Url).filter_by(value=url_value).one_or_none()
            if url_m is None:
                url_m = \
                    Url.get_or_create(value=url_value, session=db_session)[0]
                db_session.commit()
            res = url_m.to_dict()
            if url_m.checksum:
                res['checksum_value'] = url_m.checksum_value
                res['checksum_trash'] = url_m.checksum_trash
            if flask_request.method == 'POST':
                for key in ('redirect_counter''check_counter'):
                    var = flask_request.form.get(key, None)
                    if var and var == '+1':
                        if getattr(url_m, key, None) is None:
                            setattr(url_m, key)
                        else:
                            setattr(url_m, key, getattr(url_m, key) + 1)
                    elif var:
                        current_app.logger.error('Unknown input:{}:{}'.format(
                            key, var))
                db_session.add(url_m)
                db_session.commit()
                res['redirect_counter'] = url_m.redirect_counter
                res['check_counter'] = url_m.check_counter
        except OperationalError as err:
            current_app.logger.error(traceback.format_exc())
            current_app.logger.error('{}:{}\n{}:{}'.format(
                type(err), err, 'URL', url_value))
            res['error'] = str(err)
            db_session.rollback()
        finally:
            db_session.close()
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
                checksum_m = Sha256Checksum.get_or_create(
                    file_path, session=db_session)[0]
                #  if info['value'] != item['value']:  # TODO
                checksum_m.trash = False
                csm_ms.append(checksum_m)
        db_session.add_all(csm_ms)
        db_session.commit()


@cli.command('run-mitmproxy')
@click.option('--listen-host', default='127.0.0.1', help='Host for mitmproxy')
@click.option('--listen-port', default=5007, help='Host for mitmproxy')
@click.option('--debug', is_flag=True, help='Debug')
@click.option('--redirect-host', default='127.0.0.1', help='Host for mitmproxy')  # NOQA
@click.option('--redirect-port', default=5012, help='Host for mitmproxy')
def run_mitmproxy(
        listen_host: Optional[str] = '127.0.0.1',
        listen_port: Optional[int] = 5007,
        debug: Optional[bool] = False,
        redirect_host: Optional[str] = '127.0.0.1',
        redirect_port: Optional[int] = 5012
):
    assert listen_host, 'Listen host required'
    args_lines = ['--listen-host {}'.format(listen_host)]
    if listen_port:
        args_lines.append('--listen-port {}'.format(listen_port))
    args_lines.append('-s {}'.format(__file__))
    if debug:
        args_lines.append('--set=debug=true')
    if redirect_host:
        args_lines.append(
            '--set=redirect_host={}'.format(shlex.quote(redirect_host)))
    if redirect_port:
        args_lines.append(
            '--set=redirect_port={}'.format(shlex.quote(str(redirect_port))))
    mitmproxy(shlex.split(' '.join(args_lines)))


class MitmImage:

    def __init__(self):
        self.img_urls = []
        self.url_dict = {}
        self.trash_urls = []

    def load(self, loader):
        loader.add_option(
            name="redirect_host",
            typespec=Optional[str],
            default='127.0.0.1',
            help="Server host for redirect.",
        )
        loader.add_option(
            name="redirect_port",
            typespec=Optional[int],
            default=5012,
            help="Server port for redirect.",
        )
        loader.add_option(
            name="debug",
            typespec=bool,
            default=False,
            help="Turn on debugging.",
        )
        debug = ctx.options.debug \
            if ctx.options and hasattr(ctx.options, 'debug') else None
        level = logging.DEBUG if debug else logging.INFO
        logging.basicConfig(
            filename=LOG_FILE, filemode='a', level=level, format=LOG_FORMAT)
        logging.getLogger("hpack.hpack").setLevel(logging.INFO)
        logging.getLogger("hpack.table").setLevel(logging.INFO)
        logging.getLogger("PIL.PngImagePlugin").setLevel(logging.INFO)
        logging.getLogger("PIL.Image").setLevel(logging.INFO)
        logging.getLogger("urllib3.connectionpool").setLevel(logging.INFO)
        logging.info('MitmImage initiated')
        self.app = create_app(root_path=__file__)
        self.url_dict = {}

    @concurrent
    def request(self, flow: http.HTTPFlow):
        redirect_host = ctx.options.redirect_host
        redirect_port = ctx.options.redirect_port
        logger = logging.getLogger('request')
        if not redirect_host:
            return
        url = flow.request.pretty_url
        if url != flow.request.url:
            logger.debug('pretty url: {}\nurl: {}'.format(
                url, flow.request.url
            ))
        if redirect_host and \
                flow.request.host == redirect_host and \
                str(flow.request.port) == str(redirect_port):
            logger.info('SKIP REDIRECT SERVER: {}'.format(url))
            return
        session = DB.session
        try:
            app = self.app
            if flow.request.url in self.trash_urls:
                logger.info(
                    'SKIP REDIRECT TRASH: {}'.format(flow.request.url))
                with app.app_context():
                    args = flow.request.url, session
                    u_m = Url.get_or_create(*args)[0]  # type: Any
                    if u_m.check_counter is None:
                        u_m.check_counter = 1
                    else:
                        u_m.check_counter += 1
                    session.add(u_m)
                    session.commit()
                return
            u_m = None
            if url not in self.img_urls:
                with app.app_context():
                    u_m = \
                        session.query(Url) \
                        .filter_by(value=flow.request.url).one_or_none()
            if url not in self.img_urls and not u_m:
                return
            if url in self.url_dict:
                redirect_url = self.url_dict[url]
            else:
                with app.app_context():
                    if u_m is None:
                        u_m = Url.get_or_create(flow.request.url, session)[0]
                    try:
                        sc_m = u_m.checksum
                    except DetachedInstanceError:
                        u_m = Url.get_or_create(
                            flow.request.url, session)[0]
                        sc_m = u_m.checksum
                    if not sc_m:
                        logger.info('No file: {}'.format(url))
                        return
                    elif sc_m.trash:
                        logger.info(
                            'SKIP REDIRECT TRASH: {}'.format(flow.request.url))
                        if flow.request.url not in self.trash_urls:
                            self.trash_urls.append(flow.request.url)
                        return
                    redirect_url = 'http://{}:{}/i/{}.{}'.format(
                        redirect_host, redirect_port, sc_m.value, sc_m.ext)
                    self.url_dict[url] = redirect_url
            if flow.request.http_version == 'HTTP/2.0':
                flow.response = HTTPResponse(
                    'HTTP/1.1', 302, 'Found',
                    Headers(Location=redirect_url, Content_Length='0'),
                    b'')
                logger.info('REDIRECT HTTP2: {}\nTO: {}'.format(
                    url, redirect_url))
            else:
                flow.request.url = redirect_url
                logger.info(
                    'REDIRECT: {}\nTO: {}'.format(url, redirect_url))
            with app.app_context():
                if u_m is None:
                    u_m = Url.get_or_create(flow.request.url, session)[0]
                if u_m.redirect_counter is None:
                    u_m.redirect_counter = 1
                else:
                    u_m.redirect_counter += 1
                redirect_counter = u_m.redirect_counter
                check_counter = u_m.check_counter
                session.add(u_m)
                try:
                    session.commit()
                except (OperationalError, IntegrityError) as err:
                    logger.warning(
                        '{}: {}\n'
                        'error: {}\n'
                        'redirect_counter, check_counter: {}, {}\n'
                        'host, port: {}, {}'.format(
                            type(err),
                            flow.request.url,
                            err,
                            redirect_counter,
                            check_counter,
                            flow.request.host,
                            flow.request.port
                        ))
        except Exception as err:
            logger.error('{}: {}'.format(type(err), err))
            logger.error(traceback.format_exc())

    @concurrent
    def response(self, flow: http.HTTPFlow) -> None:
        """Handle response."""
        logger = logging.getLogger('response')
        redirect_host = ctx.options.redirect_host
        redirect_port = ctx.options.redirect_port
        url = flow.request.pretty_url
        try:
            if url in self.trash_urls:
                logger.info('Url on trash: {}'.format(url))
                return
            if redirect_host and \
                    flow.request.host == redirect_host and \
                    str(flow.request.port) == str(redirect_port):
                logger.info('SKIP REDIRECT SERVER: {}'.format(url))
                return
            if 'content-type' not in flow.response.headers:
                logger.debug('Unknown content-type: {}'.format(url))
                return
            content_type = flow.response.headers['content-type']
            ext = content_type.split('/')[1].split(';')[0]
            invalid_exts = [
                'svg+xml', 'x-icon', 'gif', 'vnd.microsoft.icon', 'cur']
            if not(
                    content_type.startswith('image') and
                    ext not in invalid_exts):
                return
            if url not in self.img_urls:
                self.img_urls.append(url)
            with tempfile.NamedTemporaryFile(
                    delete=False, suffix='.{}'.format(ext)) as f:
                with open(f.name, 'wb') as ff:
                    ff.write(flow.response.content)
                app = self.app
                session = DB.session
                with app.app_context():
                    u_m = Url.get_or_create(url, session)[0]  # type: Any
                    if u_m.checksum and u_m.checksum.trash:
                        self.trash_urls.append(url)
                        logger.info(
                            'SKIP TRASH: {}'.format(flow.request.url))
                        return
                    sc_m = None  # type: Any
                    if u_m.checksum and not u_m.checksum.trash:
                        sc_m = u_m.checksum
                        self.url_dict[url] = 'http://{}:{}/i/{}.{}'.format(
                            redirect_host, redirect_port, sc_m.value, sc_m.ext)
                    if not sc_m:
                        with session.no_autoflush:
                            try:
                                sc_m = Sha256Checksum.get_or_create(
                                    f.name, u_m, session)[0]
                            except OSError as err:
                                exp_txt = 'cannot identify image file'
                                if str(err).startswith(exp_txt):
                                    dbg_tmpl = \
                                        '{}:{}\nurl: {}\nfile: {}\n' \
                                        'filesize: {}'
                                    logger.debug(dbg_tmpl.format(
                                        type(err), err,
                                        flow.request.url,
                                        f.name,
                                        os.path.getsize(f.name)
                                    ))
                                else:
                                    raise err
                        self.url_dict[url] = 'http://{}:{}/i/{}.{}'.format(
                            redirect_host, redirect_port, sc_m.value, sc_m.ext)
                        try:
                            session.commit()
                        except (OperationalError, IntegrityError) as err:
                            logger.error('{}: {}\nerror: {}'.format(
                                type(err), url, str(err)))
                            return
                        logger.info('Url inbox: {}'.format(url))
                    if sc_m.trash and url not in self.trash_urls:
                        self.trash_urls.append(url)
        except Exception as err:
            logger.error('{}: {}'.format(type(err), err))
            logger.error(traceback.format_exc())

    @command.command('mitmimage.test_log')
    def test_log(self) -> None:
        logger = logging.getLogger('test_log')
        logger.debug('debug log')
        logger.info('info log')
        logger.warning('warning log')
        logger.error('error log')


addons = [
    MitmImage()
]


if __name__ == '__main__':
    cli()
