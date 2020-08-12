#!/usr/bin/env python
"""This script download all the image.

reference:
https://github.com/mitmproxy/mitmproxy/blob/master/examples/simple/internet_in_mirror.py
https://gist.github.com/denschub/2fcc4e03a11039616e5e6e599666f952
https://stackoverflow.com/a/44873382/1766261
"""
import argparse
import asyncio
import cgi
import functools
import io
import logging
import os
import pathlib
import shlex
import shutil
import signal
import sys
import tempfile
import threading
import traceback
import typing
from collections import defaultdict
from datetime import date, datetime
from typing import Any, Dict, List, Optional, Tuple, TypeVar, Union

import click
from appdirs import user_data_dir
from flask import Flask, abort, current_app, jsonify
from flask import request as flask_request
from flask import send_from_directory, url_for
from flask.cli import FlaskGroup
from flask.views import MethodView
from flask_admin import Admin, AdminIndexView
from flask_sqlalchemy import SQLAlchemy
from hashfile import hash_file
from hydrus import Client
from mitmproxy import (
    command,
    ctx,
    exceptions,
    http,
    master,
    options,
    optmanager,
    proxy
)
from mitmproxy.flow import Flow
from mitmproxy.script import concurrent
from mitmproxy.tools import cmdline
from mitmproxy.tools._main import assert_utf8_env, process_options
from mitmproxy.utils import arg_check, debug
from PIL import Image
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm.scoping import scoped_session
from sqlalchemy.sql import func  # type: ignore  # NOQA
from sqlalchemy.types import TIMESTAMP
from sqlalchemy_utils import database_exists
from sqlalchemy_utils.types import URLType

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
DB = SQLAlchemy()
# annotation
Sha256ChecksumVar = TypeVar('Sha256ChecksumVar', bound='Sha256Checksum')
UrlVar = TypeVar('UrlVar', bound='Url')
# etc
KNOWN_IMAGE_EXTS = (
    'gif', 'jpeg', 'jpg', 'png', 'svg+xml', 'vnd.microsoft.icon',
    'webp', 'x-icon',)
KNOWN_CONTENT_TYPES = tuple('image/{}'.format(x) for x in KNOWN_IMAGE_EXTS)
INVALID_IMAGE_EXTS = ['svg+xml', 'x-icon', 'gif', 'vnd.microsoft.icon', 'cur']
CACHE_SIZE = 1024


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


def scan_image_folder():
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


@cli.command('scan-image-folder')
def scan_image_folder_command():
    """Scan image folder.

    This function find problems in image folder.
    - empty filesize (trash)
    - empty ext (process info, save if image)
    - file not in database (process info, save  if image)
    - file in database but not in image folder (set trash prop = True)
    - file in db and folder, trash prop=true (set trash prop = False)
    - file in database but empty filesize (trash)
    """
    scan_image_folder()


def run(
        master_cls: typing.Type[master.Master],
        make_parser: typing.Callable[[options.Options], argparse.ArgumentParser],
        arguments: typing.Sequence[str],
        extra: typing.Callable[[typing.Any], dict] = None
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
    except SystemExit as err:
        arg_check.check()
        raise err

    try:
        opts.set(*args.setoptions, defer=True)
        optmanager.load_paths(
            opts,
            os.path.join(opts.confdir, "config.yaml"),
            os.path.join(opts.confdir, "config.yml"),
        )
        pconf = process_options(parser, opts, args)
        server: typing.Any = None
        if pconf.options.server:
            try:
                server = proxy.server.ProxyServer(pconf)
            except exceptions.ServerException as v:
                print(str(v), file=sys.stderr)
                raise v
        else:
            server = proxy.server.DummyServer(pconf)

        master.server = server
        if args.options:
            print(optmanager.dump_defaults(opts))
            #  on original function it exit with zode 0
            return master
        if args.commands:
            master.commands.dump()
            #  on original function it exit with zode 0
            return master
        if extra:
            if(args.filter_args):
                master.log.info(
                    f"Only processing flows that match "
                    f"\"{' & '.join(args.filter_args)}\"")
            opts.update(**extra(args))

        loop = asyncio.get_event_loop()
        try:
            loop.add_signal_handler(
                signal.SIGINT, getattr(master, "prompt_for_exit", master.shutdown))
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
        print("%s: %s" % (sys.argv[0], e), file=sys.stderr)
        raise e
    except (KeyboardInterrupt, RuntimeError):
        pass
    return master


def run_custom_mitmproxy(args=None) -> typing.Optional[int]:  # pragma: no cover
    if os.name == "nt":
        print("Error: mitmproxy's console interface is not supported on Windows. "
              "You can run mitmdump or mitmweb instead.", file=sys.stderr)
        return 1
    assert_utf8_env()
    from mitmproxy.tools import console
    try:
        run(console.master.ConsoleMaster, cmdline.mitmproxy, args)
    except (SystemExit, Exception) as err:
        print(err)
        import pdb
        pdb.set_trace()
    return None


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
    args_lines.append('-s {}'.format(__file__))
    args_lines.append('--view-filter {}'.format(shlex.quote(
        '~t "image\\/(?!cur|gif|svg.xml|vnd.microsoft.icon|x-icon).+"')))
    args_lines.append(
        '--set console_focus_follow={}'.format(shlex.quote('true')))
    run_custom_mitmproxy(shlex.split(' '.join(args_lines)))


class MitmImage:

    def __init__(self):
        self.data = {}
        self.lock = threading.Lock()
        self.logger = logging.getLogger()
        access_key = '918efdc1d28ae710b46fc814ee818100a102786140ede877db94cedf3d733cc1'
        self.client = Client(access_key)
        logger = logging.getLogger('mitmimage')
        logger.setLevel(logging.DEBUG)
        # create file handler which logs even debug messages
        fh = logging.FileHandler('/home/r3r/mitmimage.log')
        fh.setLevel(logging.DEBUG)
        logger.addHandler(fh)
        self.logger = logger
        self.show_downloaded_url = True
        master = getattr(ctx, 'master', None)
        self.view = master.addons.get('view') if master else None

    @classmethod
    def is_valid_content_type(
            cls, flow: http.HTTPFlow, logger: Optional[Any] = None) -> bool:
        allowed_subtype: List[str] = [
            'jpeg',
            'jpg',
            'png',
            'webp',
        ]
        disallowed_subtype: List[str] = [
            'cur',
            'gif',
            'svg+xml',
            'vnd.microsoft.icon',
            'x-icon',
        ]
        if not flow.response or 'Content-type' not in flow.response.data.headers:
            return False
        content_type = flow.response.data.headers['Content-type']
        mimetype = cgi.parse_header(content_type)[0]
        maintype, subtype = mimetype.lower().split('/')
        if maintype != 'image':
            return False
        if subtype not in allowed_subtype:
            if subtype not in disallowed_subtype and logger:
                logger.info('unknown subtype:{}'.format(subtype))
            return False
        return True

    @classmethod
    def remove_from_view(cls, view, flow):
        f = flow  # compatibility
        if f in view._view:
            # We manually pass the index here because multiple flows may have the same
            # sorting key, and we cannot reconstruct the index from that.
            idx = view._view.index(f)
            view._view.remove(f)
            view.sig_view_remove.send(view, flow=f, index=idx)

    @classmethod
    def upload(
            cls,
            flow: http.HTTPFlow,
            client: Client,
            logger: Optional[Any]=None,
            associated_url: Optional[str]=None) -> Optional[Dict[str, str]]:
        content = flow.response.get_content()
        url = flow.request.pretty_url
        if content is None:
            if logger:
                logger.debug('url dont have content:\n{}'.format(url))
            return
        # upload file
        upload_resp = client.add_file(io.BytesIO(content))
        if logger:
            logger.info('uploaded:{},{},{}'.format(
                upload_resp['status'], upload_resp['hash'][:7], url
            ))

        if associated_url is None:
            associated_url = url
        client.associate_url([upload_resp['hash'], ], [associated_url])
        # show uploaded image
        client.add_url(associated_url, page_name='mitmimage')
        return upload_resp

    @functools.lru_cache(CACHE_SIZE)
    def get_url_files(self, url: str):
        return self.client.get_url_files(url)

    @concurrent
    def request(self, flow: http.HTTPFlow):
        url = flow.request.pretty_url
        with self.lock:
            if (url not in self.data) or (not self.data[url]['hydrus']):
                return
            url_file_statuses = self.data[url]['hydrus'].get('url_file_statuses', None)
        if not url_file_statuses:
            return
        # turn url_file_statuses from list of hashes to hash dict
        hash_dict = defaultdict(list)
        for status in url_file_statuses:
            hash_dict[status['hash']].append(status['status'])
        if len(hash_dict.keys()) != 1:
            self.logger.debug('following url have multiple hashes:\n{}'.format(url))
            return
        url_hash, statuses = list(hash_dict.items())[0]
        statuses = list(set(statuses))
        if statuses == [3]:
            return
        elif not all(x in [1, 2] for x in statuses):
            self.logger.debug(
                'mixed status:{},{}'.format(statuses, url))
            return
        file_data = self.client.get_file(hash_=url_hash)
        flow.response = http.HTTPResponse.make(
            content=file_data.content,
            headers={'Content-Type': file_data.headers['Content-Type']})
        self.logger.info('cached:{},{},{}'.format(statuses, url_hash[:7], url))
        self.remove_from_view(self.view, flow)

    @concurrent
    def response(self, flow: http.HTTPFlow) -> None:
        """Handle response."""
        if not self.is_valid_content_type(flow, logger=self.logger):
            return
        if flow.response is None:
            return
        # hydrus url files response
        url = flow.request.pretty_url
        with self.lock:
            if url not in self.data:
                self.data[url] = {'hydrus': None}
            url_data = self.data[url].get('hydrus', None)
            if not url_data:
                #  huf = hydrus url files
                huf_resp = self.get_url_files(flow.request.url)
                self.data[url]['hydrus'] = url_data = huf_resp
                url_file_statuses = huf_resp.get('url_file_statuses', None)
                if (url_file_statuses and self.show_downloaded_url and
                        any(x['status'] == 2 for x in url_file_statuses)):
                    self.client.add_url(url, page_name='mitmimage')
            if url_data.get('url_file_statuses', None):
                self.remove_from_view(self.view, flow)
                return
            # upload file
            upload_resp = self.upload(
                flow, self.client, self.logger,
                url_data.get('normalised_url', None))
            # remove from view
            self.remove_from_view(self.view, flow)
            if not upload_resp:
                return
            # update data
            if 'url_file_statuses' in self.data[url]['hydrus']:
                self.data[url]['hydrus']['url_file_statuses'].append(upload_resp)
            else:
                self.data[url]['hydrus']['url_file_statuses'] = [upload_resp]

    # command

    @command.command('mitmimage.log_hello')
    def log_hello(self):
        ctx.log.info('mitmimage: hello')

    @command.command("mitmimage.clear_data")
    def clear_data(self) -> None:
        self.data = {}
        ctx.log.info('mitmimage: data cleared')

    @command.command("mitmimage.show_downloaded_url")
    def clear_url_data(self, show: bool) -> None:
        self.show_downloaded_url = show

    @command.command('mitmimage.pdb')
    def pdb(self):
        import pdb
        pdb.set_trace()

    @command.command('mitmimage.ipdb')
    def ipdb(self):
        import ipdb
        ipdb.set_trace()

    @command.command('mitmimage.ipdb_flow')
    def ipdb_flow(self, flows: typing.Sequence[Flow]) -> None:
        import ipdb
        ipdb.set_trace()

    @command.command('mitmimage.log_info')
    def log_info(self):
        ctx.log.info('cache:{},{}\nurl:{}'.format(
            'get_url_files', self.get_url_files.cache_info(),
            len(list(self.data.keys()))
        ))

    @command.command('mitmimage.remove_flow_with_data')
    def remove_flow_with_data(self):
        items = filter(
            lambda item: item[1].response and 
            item[1].response.content is not None,
            self.view._store.items())
        self.view.remove([x[1] for x in items])

    @command.command('mitmimage.upload_flow')
    def upload_flow(self, flows: typing.Sequence[Flow]) -> None:
        list(map(
            lambda flow: self.upload(flow, self.client, self.logger), flows))



addons = [
    MitmImage()
]


if __name__ == '__main__':
    cli()
