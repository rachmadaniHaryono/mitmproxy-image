#!/usr/bin/env python
# -*- coding: utf-8 -*-
import asyncio
import cgi
import io
import logging
import mimetypes
import os
import re
from collections import Counter, defaultdict, namedtuple
from enum import Enum
from itertools import islice
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union
from urllib.parse import unquote_plus, urlparse

import magic
import yaml
from hydrus import APIError, Client, ConnectionError, ImportStatus
from mitmproxy import command, ctx, http
from mitmproxy.flow import Flow
from mitmproxy.script import concurrent
from pythonjsonlogger import jsonlogger


class LogKey(Enum):
    FLOW = "f"
    KEY = "k"
    HASH = "hash"
    MESSAGE = "message"
    MIME = "m"
    ORIGINAL = "o"
    STATUS = "s"
    TARGET = "t"
    URL = "u"


AURegex = namedtuple("AURegex", ["cpatt", "url_fmt", "log_flag", "page_name"])
EMPTY_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def nth(iterable, n, default=None):
    """Returns the nth item or a default value."""
    return next(islice(iterable, n, None), default)


def first_true(iterable, default=None, pred=None):
    """
    Returns the first true value in the iterable.

    If no true value is found, returns *default*

    If *pred* is not None, returns the first item for which
    ``pred(item) == True`` .
    """
    return next(filter(pred, iterable), default)


def get_mimetype(
    flow: Optional[http.HTTPFlow] = None, url: Optional[str] = None
) -> Optional[str]:
    """Get mimetype from flow or url.

    >>> from types import SimpleNamespace
    >>> get_mimetype(SimpleNamespace(response={}), 'http://example.com')
    Traceback (most recent call last):
    ...
    ValueError: Only require flow or url

    >>> get_mimetype(url='http://example.com/1.jpg')
    'image/jpeg'

    >>> get_mimetype(SimpleNamespace(response=SimpleNamespace(data=SimpleNamespace(
    ...     headers={'Content-type': 'image/jpeg'}))))
    'image/jpeg'

    >>> get_mimetype()
    """
    if all([flow, url]):
        raise ValueError("Only require flow or url")
    header = None
    try:
        if flow is not None and flow.response:
            header = flow.response.data.headers["Content-type"]
    except Exception as err:
        logging.getLogger().debug(str(err), exc_info=True)
        if flow is not None:
            url = getattr(getattr(flow, "request", None), "pretty_url", None)
    if url is not None:
        # no query url
        nq_url = urlparse(url)._replace(query="").geturl()  # type: ignore
        nq_url_type = mimetypes.guess_type(nq_url)
        header = nq_url_type[0] if len(nq_url_type) > 0 else None
    if header is None:
        return None
    # parsed header
    p_header = cgi.parse_header(header)
    return p_header[0] if len(p_header) > 0 else None


def get_connection_error_message(err):
    """get formatted text from ConnectionError."""
    return "{}:{}".format(type(err).__name__, re.sub(r"0x.*>", ">", str(err)))


class CustomJsonFormatter(jsonlogger.JsonFormatter):
    def add_fields(self, log_record, record, message_dict):
        super(CustomJsonFormatter, self).add_fields(log_record, record, message_dict)
        log_record["p"] = "{}:{}:{}".format(
            record.levelname[0], record.funcName, record.lineno
        )
        if not log_record.get("message"):
            del log_record["message"]


class MitmImage:

    url_data: Dict[str, Set[str]]
    hash_data: Dict[str, str]
    config: Dict[str, Any]

    default_access_key = (
        "918efdc1d28ae710b46fc814ee818100a102786140ede877db94cedf3d733cc1"
    )
    default_config_path = os.path.expanduser("~/mitmimage.yaml")
    client = Client(default_access_key)

    def __init__(self):
        self.clear_data()
        self.config = {}
        self.block_regex = []
        self.add_url_regex = []
        # logger
        logger = logging.getLogger("mitmimage")
        logger.setLevel(logging.INFO)
        # create file handler
        fh = logging.FileHandler(os.path.expanduser("~/mitmimage.log"))
        fh.setLevel(logging.INFO)
        fh.setFormatter(CustomJsonFormatter("%(p)s %(message)s"))
        logger.addHandler(fh)
        self.logger = logger
        #  other
        try:
            if hasattr(ctx, "master"):
                self.view = ctx.master.addons.get("view")
        except Exception as err:
            self.logger.exception("{}".format(str(err)))
            self.view = None
        self.upload_queue = asyncio.Queue()
        self.post_upload_queue = asyncio.Queue()
        self.client_queue = asyncio.Queue()
        self.client_lock = asyncio.Lock()
        self.cached_urls = set()
        self.page_name = "mitmimage"
        self.additional_page_name = "mitmimage_plus"
        self.remove_view_enable = True

    def is_valid_content_type(
        self,
        flow: Optional[http.HTTPFlow] = None,
        url: Optional[str] = None,
        mimetype: Optional[str] = None,
    ) -> bool:
        """check if flow, url or mimetype is valid.

        If mimetype parameter is given ignore flow and url paramter."""
        if not mimetype:
            mimetype = get_mimetype(flow, url)
        if not mimetype:
            return False
        try:
            if mimetype == "jpg":
                maintype, subtype = "image", "jpeg"
            else:
                maintype, subtype = mimetype.lower().split("/")
            subtype = subtype.lower()
        except ValueError as err:
            self.logger.debug(err, exc_info=True)
            self.logger.info(
                {
                    LogKey.MIME.value: mimetype,
                    LogKey.URL.value: url,
                    LogKey.FLOW.value: str(flow),
                    LogKey.MESSAGE.value: "unknown",
                }
            )
            return False
        mimetype_sets = self.config.get("mimetype", [])
        if not mimetype_sets and maintype == "image":
            return True
        if (
            mimetype_sets
            and any(maintype == x[0] for x in mimetype_sets)
            and any(subtype.lower() == x[1] for x in mimetype_sets)
        ):
            return True
        return False

    def remove_from_view(self, flow: Union[http.HTTPFlow, Flow]):
        if not self.remove_view_enable:
            return
        # compatibility
        f = flow
        view = self.view

        if view is None:
            return

        if f.id in view._store:
            if f in view._view:
                # We manually pass the index here because multiple flows may have the same
                # sorting key, and we cannot reconstruct the index from that.
                idx = view._view.index(f)
                view._view.remove(f)
                try:
                    view.sig_view_remove.send(view, flow=f, index=idx)
                except ValueError as err:
                    self.logger.debug(
                        str(err),
                        exc_info=True,
                    )
            del view._store[f.id]
            view.sig_store_remove.send(view, flow=f)

    def get_hashes(self, url: str, from_hydrus: str = "on_empty") -> Set[str]:
        """get hashes based on url input.

        If `from_hydrus` is `always`, ask client everytime.
        If `from_hydrus` is `on_empty`, ask client only when url not in self.url_data.

        >>> # url don't have any hashes on self.url_data and client
        >>> MitmImage().get_hashes('http://example.com')
        set()
        """
        assert from_hydrus in ["always", "on_empty"]
        hashes: Set[str] = self.url_data.get(url, set())
        if hashes and from_hydrus == "on_empty":
            hashes.discard(EMPTY_HASH)
            return hashes
        huf_resp = self.client.get_url_files(url)
        # ufs = get_url_status
        for ufs in huf_resp["url_file_statuses"]:
            if ufs["hash"] == EMPTY_HASH:
                continue
            self.url_data[url].add(ufs["hash"])
            self.hash_data[ufs["hash"]] = ufs["status"]
        hashes = self.url_data[url]
        hashes.discard(EMPTY_HASH)
        return hashes

    def upload(self, flow: Union[http.HTTPFlow, Flow]) -> Optional[Dict[str, str]]:
        url = flow.request.pretty_url  # type: ignore
        response = flow.response  # type: ignore
        if response is None:
            self.logger.debug(
                {LogKey.MESSAGE.value: "no response", LogKey.URL.value: url}
            )
            return None
        content = response.get_content()
        if content is None:
            self.logger.debug(
                {LogKey.MESSAGE.value: "no content", LogKey.URL.value: url}
            )
            return None
        # upload file
        upload_resp = self.client.add_file(io.BytesIO(content))
        self.logger.info(
            {LogKey.STATUS.value: upload_resp["status"], LogKey.URL.value: url}
        )
        self.client_queue.put_nowait(
            (
                "associate_url",
                [
                    [
                        upload_resp["hash"],
                    ],
                    [url],
                ],
                {},
            )
        )
        # update data
        self.url_data[url].add(upload_resp["hash"])
        self.hash_data[upload_resp["hash"]] = upload_resp["status"]
        return upload_resp

    def load_config(self, config_path):
        try:
            with open(config_path) as f:
                self.config = yaml.safe_load(f)
                view_filter = self.config.get("view_filter", None)
                ctx_options = hasattr(ctx, "options")
                if view_filter:
                    if ctx_options:
                        ctx.options.view_filter = view_filter
                    if hasattr(ctx, "log"):
                        ctx.log.info("view_filter: {}".format(view_filter))
                BlockRegex = namedtuple("BlockRegex", ["cpatt", "name", "log_flag"])
                self.host_block_regex = self.config.get("host_block_regex", [])
                self.host_block_regex = [re.compile(x) for x in self.host_block_regex]
                self.block_regex = self.config.get("block_regex", [])
                self.block_regex = [
                    BlockRegex(re.compile(x[0]), x[1], nth(x, 2, False))
                    for x in self.block_regex
                ]
                if ctx_options:
                    ctx.log.info(
                        "mitmimage: load {} block regex.".format(len(self.block_regex))
                    )
                    ctx.log.info(
                        "mitmimage: load {} url filename block regex.".format(
                            len(self.config.get("block_url_filename_regex", []))
                        )
                    )
                self.add_url_regex = self.config.get("add_url_regex", [])
                self.add_url_regex = [
                    AURegex(
                        re.compile(item[0]),
                        item[1],
                        nth(item, 2, False),
                        nth(item, 4, self.additional_page_name),
                    )
                    for item in self.add_url_regex
                ]
        except Exception as err:
            if hasattr(ctx, "log"):
                log_msg = "mitmimage: error loading config, {}".format(err)
                ctx.log.error(log_msg)
                self.logger.exception(
                    "{}\n{}".format(
                        err.message if hasattr(err, "message") else str(err), log_msg
                    )
                )

    # mitmproxy add on class' method

    def load(self, loader):  # pragma: no cover
        loader.add_option(
            name="hydrus_access_key",
            typespec=str,
            default=self.default_access_key,
            help="Hydrus Access Key",
        )
        loader.add_option(
            name="mitmimage_config",
            typespec=Optional[str],
            default=self.default_config_path,
            help="mitmimage config file",
        )
        loader.add_option(
            name="mitmimage_remove_view",
            typespec=bool,
            default=True,
            help="mitmimage will remove view when necessary",
        )
        loader.add_option(
            name="mitmimage_debug",
            typespec=bool,
            default=False,
            help="Set mitmimage logging level to DEBUG",
        )

    def configure(self, updates):
        if "hydrus_access_key" in updates:
            hydrus_access_key = ctx.options.hydrus_access_key
            if hydrus_access_key and hydrus_access_key != self.client._access_key:
                self.client = Client(hydrus_access_key)
                ctx.log.info("mitmimage: client initiated with new access key.")
        if "mitmimage_config" in updates and ctx.options.mitmimage_config:
            self.load_config(ctx.options.mitmimage_config)
        if "mitmimage_remove_view" in updates:
            self.remove_view_enable = ctx.options.mitmimage_remove_view
            ctx.log.info("mitmimage: remove view: {}.".format(self.remove_view_enable))
        if "mitmimage_debug" in updates:
            if ctx.options.mitmimage_debug:
                self.logger.setLevel(logging.DEBUG)
                self.logger.handlers[0].setLevel(logging.DEBUG)
            else:
                self.logger.setLevel(logging.INFO)
                self.logger.handlers[0].setLevel(logging.INFO)
            ctx.log.info("mitmimage: log level: {}.".format(self.logger.level))

    def get_url_filename(self, url: str, max_len: int = 120) -> Optional[str]:
        """Get url filename.

        >>> MitmImage().get_url_filename('http://example.com/1.jpg')
        '1'
        >>> MitmImage().get_url_filename('http://example.com/1234.jpg', max_len=1)
        """
        url_filename = None
        try:
            url_filename = unquote_plus(Path(urlparse(url).path).stem)
            if url_filename:
                for item in self.config.get("block_url_filename_regex", []):
                    if re.match(item[0], url):
                        self.logger.debug("skip filename:{},{}".format(item[1], url))
                        self.logger.debug(
                            {
                                LogKey.KEY.value: "skip filename",
                                LogKey.MESSAGE.value: item[1],
                                LogKey.URL.value: url,
                            }
                        )
                        return None
            if url_filename and len(url_filename) > max_len:
                self.logger.info(
                    {
                        LogKey.MESSAGE.value: "url filename too long",
                        LogKey.URL.value: "url",
                    }
                )

                return None
        except Exception as err:
            self.logger.exception(str(err))
        return url_filename

    def add_additional_url(self, url: str):
        """add additional url.

        >>> from unittest import mock
        >>> obj = MitmImage()
        >>> obj.add_url_regex = [AURegex(
        ...     re.compile(r'https://example.com/(.*)'),
        ...     'https://example.com/sub/{0}', False, obj.additional_page_name)]
        >>> obj.client_queue.put_nowait = mock.Mock()
        >>> obj.add_additional_url('https://example.com/1.jpg')
        >>> obj.client_queue.put_nowait.assert_called_once_with((
        ...     'add_url', [], {
        ...         'url': 'https://example.com/sub/1.jpg',
        ...         'page_name': obj.additional_page_name,
        ...         'service_names_to_additional_tags': {
        ...             'my tags': ['filename:1']
        ...         }
        ...     }
        ... ))

        """
        url_sets = []
        # rs = regex set
        for rs in self.add_url_regex:
            match = rs.cpatt.match(url)
            if match and match.groups():
                new_url = rs.url_fmt.format(*match.groups())
                if new_url == url:
                    continue
                url_sets.append((new_url, rs.page_name))
                log_msg = {LogKey.ORIGINAL.value: url, LogKey.TARGET.value: new_url}
                if rs.log_flag:
                    self.logger.info(log_msg)
                else:
                    self.logger.debug(log_msg)
        if url_sets:
            self.logger.info(
                {
                    LogKey.ORIGINAL.value: url,
                    LogKey.TARGET.value: set([x[0] for x in url_sets]),
                }
            )
            for (new_url, page_name) in url_sets:
                kwargs = {"page_name": page_name, "url": new_url}
                filename = self.get_url_filename(new_url)
                if filename:
                    kwargs["service_names_to_additional_tags"] = {
                        "my tags": ["filename:{}".format(filename)]
                    }
                args: Tuple[str, List[str], Dict[str, Any]] = (
                    "add_url",
                    [],
                    kwargs,
                )
                self.client_queue.put_nowait(args)

    async def client_worker(self):
        queue = self.client_queue
        while True:
            # Get a "work item" out of the queue.
            try:
                cmd, args, kwargs = await queue.get()
                msg = {LogKey.MESSAGE.value: "cmd:{}".format(cmd)}
                if args:
                    msg["args"] = args
                if kwargs:
                    msg["kwargs"] = kwargs
                self.logger.debug(msg)
                async with self.client_lock:
                    getattr(self.client, cmd)(*args, **kwargs)
            except ConnectionError as err:
                self.logger.info(
                    {LogKey.MESSAGE.value: get_connection_error_message(err)}
                )
            except Exception as err:
                self.logger.error(
                    err.message if hasattr(err, "message") else str(err), exc_info=True
                )
            # Notify the queue that the "work item" has been processed.
            queue.task_done()

    async def post_upload_worker(self):
        while True:
            try:
                # Get a "work item" out of the queue.
                url, upload_resp, referer = await self.post_upload_queue.get()
                if upload_resp:
                    self.client_queue.put_nowait(
                        (
                            "associate_url",
                            [
                                [
                                    upload_resp["hash"],
                                ],
                                [url],
                            ],
                            {},
                        )
                    )
                    # update data
                    self.url_data[url].add(upload_resp["hash"])
                    self.hash_data[upload_resp["hash"]] = upload_resp["status"]
                tags = []
                url_filename = self.get_url_filename(url)
                if url_filename:
                    tags.append("filename:{}".format(url_filename))
                if referer:
                    tags.append("referer:{}".format(referer))
                kwargs: Dict[str, Any] = {"page_name": "mitmimage"}
                if tags:
                    kwargs["service_names_to_additional_tags"] = {"my tags": tags}
                self.client_queue.put_nowait(("add_url", [url], kwargs))
            except Exception as err:
                self.logger.error(
                    err.message if hasattr(err, "message") else str(err), exc_info=True
                )
            # Notify the queue that the "work item" has been processed.
            self.post_upload_queue.task_done()

    async def upload_worker(self):
        while True:
            try:
                # Get a "work item" out of the queue.
                flow = await self.upload_queue.get()
                url = flow.request.pretty_url  # type: ignore
                response = flow.response  # type: ignore
                if response is None:
                    self.logger.debug(
                        {
                            LogKey.MESSAGE.value: "no response url",
                            LogKey.URL.value: url,
                        }
                    )
                    self.upload_queue.task_done()
                    return
                content = response.get_content()
                if content is None:
                    self.logger.debug(
                        {
                            LogKey.MESSAGE.value: "no content url",
                            LogKey.URL.value: url,
                        }
                    )
                    self.upload_queue.task_done()
                    return
                # upload file
                async with self.client_lock:
                    upload_resp = self.client.add_file(io.BytesIO(content))
                status = upload_resp["status"]
                referer = flow.request.headers.get("referer", None)
                hash_ = upload_resp.get("hash", None)
                if status in [
                    ImportStatus.Exists,
                    ImportStatus.PreviouslyDeleted,
                    ImportStatus.Success,
                ]:
                    self.post_upload_queue.put_nowait((url, upload_resp, referer))
                elif status in [ImportStatus.Failed, ImportStatus.Vetoed] and hash_:
                    self.url_data[url].add(hash_)
                    self.hash_data[hash_] = status
                else:
                    self.logger.debug(upload_resp)
                if self.logger.level == logging.DEBUG:
                    self.logger.debug(
                        {
                            LogKey.HASH.value: hash_,
                            LogKey.STATUS.value: status,
                            LogKey.URL.value: url,
                        }
                    )
                else:
                    self.logger.info(
                        {
                            LogKey.STATUS.value: status,
                            LogKey.URL.value: url,
                        }
                    )
            except ConnectionError as err:
                self.logger.error(
                    {
                        LogKey.MESSAGE.value: get_connection_error_message(err),
                        LogKey.URL.value: url,
                    }
                )
            except Exception as err:
                self.logger.error(
                    err.message if hasattr(err, "message") else str(err), exc_info=True
                )
            self.upload_queue.task_done()

    @concurrent
    def request(self, flow: http.HTTPFlow):
        try:
            url: str = flow.request.pretty_url
            self.add_additional_url(url)
            if flow.request.method == "POST":
                self.remove_from_view(flow=flow)
                return
            match = first_true(
                self.host_block_regex, pred=lambda x: x.match(flow.request.pretty_host)
            )
            if match:
                self.logger.debug(
                    {LogKey.URL.value: url, LogKey.KEY.value: "host block"}
                )
                self.remove_from_view(flow=flow)
                return
            match = first_true(self.block_regex, pred=lambda x: x.cpatt.match(url))
            if match:
                if match.log_flag:
                    self.logger.debug(
                        {
                            LogKey.KEY.value: "rskip",
                            LogKey.MESSAGE.value: match.name,
                            LogKey.URL.value: url,
                        }
                    )
                self.remove_from_view(flow=flow)
                return
            hashes = self.get_hashes(url, "always")
            if not hashes and not self.is_valid_content_type(url=url):
                return
            if len(hashes) == 1:
                hash_: str = next(iter(hashes))
                status = self.hash_data.get(hash_, None)
                if status is not None and status in [
                    ImportStatus.PreviouslyDeleted,
                    ImportStatus.Importable,
                    ImportStatus.Failed,
                ]:
                    return
                try:
                    file_data = self.client.get_file(hash_=hash_)
                except APIError as err:
                    self.logger.error(
                        {
                            LogKey.HASH.value: hash_,
                            LogKey.MESSAGE.value: "{}:{}".format(
                                type(err).__name__, err
                            ),
                            LogKey.STATUS.value: status,
                            LogKey.URL.value: url,
                        }
                    )
                    return
                flow.response = http.HTTPResponse.make(
                    content=file_data.content,
                    headers=dict(file_data.headers),
                )
                if url not in self.cached_urls:
                    self.cached_urls.add(url)
                self.client_queue.put_nowait(
                    ("add_url", [url], {"page_name": "mitmimage"})
                )
                referer = flow.request.headers.get("referer", None)
                self.post_upload_queue.put_nowait((url, None, referer))
                self.logger.info(
                    {LogKey.URL.value: url, LogKey.MESSAGE.value: "add and cached"}
                )
                self.remove_from_view(flow=flow)
            elif hashes:
                self.logger.debug(
                    {
                        "hash count": len(hashes),
                        "url hash": "\n".join(hashes),
                        LogKey.URL.value: url,
                    }
                )
            else:
                self.logger.debug(
                    {
                        LogKey.MESSAGE.value: "no hash",
                        LogKey.URL.value: url,
                    }
                )
        except ConnectionError as err:
            self.logger.error(
                {
                    LogKey.MESSAGE.value: get_connection_error_message(err),
                    LogKey.URL.value: url,
                }
            )
        except Exception as err:
            self.logger.exception(str(err))

    @concurrent
    def response(self, flow: http.HTTPFlow) -> None:
        """Handle response."""
        try:
            url = flow.request.pretty_url
            match = first_true(
                self.host_block_regex, pred=lambda x: x.match(flow.request.pretty_host)
            )
            if match:
                self.logger.debug(
                    {LogKey.URL.value: url, LogKey.KEY.value: "host block"}
                )
                self.remove_from_view(flow=flow)
                return
            match = first_true(self.block_regex, pred=lambda x: x.cpatt.match(url))
            if match:
                if match.log_flag:
                    self.logger.debug(
                        {
                            LogKey.KEY.value: "rskip",
                            LogKey.MESSAGE.value: match.name,
                            LogKey.URL.value: url,
                        }
                    )
                self.remove_from_view(flow)
                return
            mimetype = magic.from_buffer(flow.response.content[:2049], mime=True)
            if mimetype is None:
                self.logger.debug(
                    {
                        LogKey.KEY.value: "no mimetype",
                        LogKey.MESSAGE.value: vars(flow.response),
                        LogKey.URL.value: url,
                    }
                )
            elif not self.is_valid_content_type(mimetype=mimetype):
                self.remove_from_view(flow)
                return
            # skip when it is cached
            if url in self.cached_urls:
                self.remove_from_view(flow)
                return
            hashes = self.get_hashes(url, "on_empty")
            single_hash_data = None
            if hashes and len(hashes) == 1:
                single_hash_data = self.hash_data.get(next(iter(hashes)), None)
            if not hashes or single_hash_data == ImportStatus.Importable:
                self.upload_queue.put_nowait(flow)
            elif single_hash_data in [
                ImportStatus.Failed,
                ImportStatus.PreviouslyDeleted,
            ]:
                # NOTE: don't do anything to it
                pass
            else:
                # NOTE: add referer & url filename to url
                referer = flow.request.headers.get("referer", None)
                self.post_upload_queue.put_nowait((url, None, referer))
                hashes_status = [(self.hash_data.get(x, None), x) for x in hashes]
                msg = {
                    LogKey.KEY.value: "add",
                    LogKey.URL.value: url,
                }
                if len(hashes_status) == 1:
                    msg.update(
                        {
                            LogKey.HASH.value: hashes_status[0][1],
                            LogKey.STATUS.value: str(hashes_status[0][0]),
                        }
                    )
                else:
                    msg.update({LogKey.MESSAGE.value: str(hashes_status)})
                self.logger.info(msg)
            self.remove_from_view(flow)
        except ConnectionError as err:
            self.logger.error(
                {
                    LogKey.MESSAGE.value: get_connection_error_message(err),
                    LogKey.URL.value: url,
                }
            )
        except Exception as err:
            self.logger.exception(str(err))

    # command

    @command.command("mitmimage.log_hello")
    def log_hello(self):  # pragma: no cover
        ctx.log.info("mitmimage: hello")

    @command.command("mitmimage.clear_data")
    def clear_data(self) -> None:
        self.url_data: Dict[str, Set[str]] = defaultdict(set)
        self.hash_data: Dict[str, ImportStatus] = {}
        if hasattr(ctx, "log"):
            ctx.log.info("mitmimage: data cleared")

    @command.command("mitmimage.ipdb")
    def ipdb(self, flows: Sequence[Flow] = None) -> None:  # pragma: no cover
        import ipdb

        ipdb.set_trace()

    @command.command("mitmimage.log_info")
    def log_info(self):
        raise NotImplementedError

    @command.command("mitmimage.remove_flow_with_data")
    def remove_flow_with_data(self):
        items = filter(
            lambda item: item[1].response and item[1].response.content is not None,
            self.view._store.items(),
        )
        self.view.remove([x[1] for x in items])

    @command.command("mitmimage.upload_flow")
    def upload_flow(self, flows: Sequence[Flow], remove: bool = False) -> None:
        resp_history = []
        for flow in flows:
            url = flow.request.pretty_url  # type: ignore
            self.add_additional_url(url)
            match = first_true(self.block_regex, pred=lambda x: x.cpatt.match(url))
            if match:
                if match.log_flag:
                    [
                        x.debug(
                            {
                                LogKey.KEY.value: "rskip",
                                LogKey.MESSAGE.value: match.name,
                                LogKey.URL.value: url,
                            }
                        )
                        for x in [self.logger, ctx.log]
                    ]
                self.remove_from_view(flow)
                continue
            resp = self.upload(flow)
            self.client_queue.put_nowait(("add_url", [url], {"page_name": "mitmimage"}))
            resp_history.append(resp)
            if remove and resp is not None:
                self.remove_from_view(flow)
        data = [x["status"] for x in resp_history if x is not None]
        if data:
            [x.info(Counter(data)) for x in [self.logger, ctx.log]]
        else:
            [x.info("upload finished") for x in [self.logger, ctx.log]]
