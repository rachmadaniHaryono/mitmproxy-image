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
from pathlib import Path
from typing import Any, Dict, Optional, Sequence, Set, Union
from urllib.parse import unquote_plus, urlparse, urlencode, urlunparse, parse_qsl

import magic
import yaml
from hydrus import APIError, Client, ConnectionError, ImportStatus, TagAction
from mitmproxy import command, ctx, http
from mitmproxy.flow import Flow
from mitmproxy.script import concurrent
from more_itertools import first_true, nth
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


def get_mimetype(flow: Optional[http.HTTPFlow] = None, url: Optional[str] = None) -> Optional[str]:
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
        logging.getLogger().exception(str(err))
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


class CustomJsonFormatter(jsonlogger.JsonFormatter):
    def add_fields(self, log_record, record, message_dict):  # pragma: no cover
        super(CustomJsonFormatter, self).add_fields(log_record, record, message_dict)
        log_record["p"] = "{}:{}:{}".format(record.levelname[0], record.funcName, record.lineno)
        if not log_record.get("message"):
            del log_record["message"]


class MitmImage:

    url_data: Dict[str, Set[str]]
    hash_data: Dict[str, str]
    config: Dict[str, Any]

    default_access_key = "918efdc1d28ae710b46fc814ee818100a102786140ede877db94cedf3d733cc1"
    client = Client(default_access_key)
    # default path
    default_config_path = os.path.expanduser("~/mitmimage.yaml")
    default_log_path = os.path.expanduser("~/mitmimage.log")
    # page name
    page_name = "mitmimage"
    additional_page_name = "mitmimage_plus"

    def __init__(self):
        self.clear_data()
        self.block_regex = []
        self.add_url_regex = []
        # logger
        logger = logging.getLogger("mitmimage")
        logger.setLevel(logging.INFO)
        self.logger = logger
        self.set_log_path(self.default_log_path)
        #  other
        #  NOTE config attribute is created here because it may not initiated on load_config
        self.config = {}
        self.load_config(self.default_config_path)
        try:
            if hasattr(ctx, "master"):  # pragma: no cover
                self.view = ctx.master.addons.get("view")
        except Exception as err:  # pragma: no cover
            self.logger.exception(str(err))
            self.view = None
        self.host_block_regex = []
        self.block_regex = []
        self.upload_queue = asyncio.Queue()
        self.post_upload_queue = asyncio.Queue()
        self.client_queue = asyncio.Queue()
        self.client_lock = asyncio.Lock()
        self.cached_urls = set()
        self.remove_view_enable = True
        self.skip_flow = set()

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
        except ValueError as err:  # pragma: no cover
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

    def remove_from_view(self, flow: Union[http.HTTPFlow, Flow]):  # pragma: no cover
        """remove flow from view.

        This supposedly copy from `mitmproxy.addons.view.View.remove` class method.

        But it will not kill the flow because it may still be needed to load the page.
        """
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
            self.logger.debug({LogKey.MESSAGE.value: "no response", LogKey.URL.value: url})
            return None
        content = response.get_content()
        if content is None:
            self.logger.debug({LogKey.MESSAGE.value: "no content", LogKey.URL.value: url})
            return None
        # upload file
        upload_resp = self.client.add_file(io.BytesIO(content))
        self.logger.info({LogKey.STATUS.value: upload_resp["status"], LogKey.URL.value: url})
        self.client_queue.put_nowait(
            (
                "associate_url",
                {
                    "hashes": [
                        upload_resp["hash"],
                    ],
                    "add": [url],
                },
            )
        )
        # update data
        self.url_data[url].add(upload_resp["hash"])
        self.hash_data[upload_resp["hash"]] = upload_resp["status"]
        return upload_resp

    def load_config(self, config_path):  # pragma: no cover
        """Load config."""
        try:
            with open(config_path) as f:
                self.config = yaml.safe_load(f)
                view_filter = self.config.get("view_filter", None)
                if view_filter and hasattr(ctx, "options"):
                    ctx.options.view_filter = view_filter
                if self.ctx_log:
                    ctx.log.info("mitmimage: view filter: {}".format(view_filter))
                BlockRegex = namedtuple("BlockRegex", ["cpatt", "name", "log_flag"])
                self.host_block_regex = self.config.get("host_block_regex", [])
                self.host_block_regex = [re.compile(x) for x in self.host_block_regex]
                self.block_regex = self.config.get("block_regex", [])
                self.block_regex = [
                    BlockRegex(re.compile(x[0]), x[1], nth(x, 2, False)) for x in self.block_regex
                ]
                if self.ctx_log:
                    ctx.log.info("mitmimage: load {} block regex.".format(len(self.block_regex)))
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
            self.logger.exception(str(err))
            if self.ctx_log:
                ctx.log.error("mitmimage: error loading config, {}".format(err))

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
        loader.add_option(
            name="mitmimage_log_file",
            typespec=Optional[str],
            default=self.default_log_path,
            help="Set mitmimage log file",
        )

    def set_log_path(self, filename: str):
        """Set log path."""
        try:
            filename = os.path.expanduser(filename)
            for hdlr in self.logger.handlers:
                self.logger.removeHandler(hdlr)
            fh = logging.FileHandler(filename)
            fh.setLevel(self.logger.getEffectiveLevel())
            fh.setFormatter(CustomJsonFormatter("%(p)s %(message)s"))
            self.logger.addHandler(fh)
            if self.ctx_log:  # pragma: no cover
                ctx.log.info("mitmimage: log path: {}.".format(filename))
        except Exception as err:  # pragma: no cover
            self.logger.exception(str(err))

    def configure(self, updates):  # pragma: no cover
        log_msg = []
        if "hydrus_access_key" in updates:
            hydrus_access_key = ctx.options.hydrus_access_key
            if hydrus_access_key and hydrus_access_key != self.client._access_key:
                self.client = Client(hydrus_access_key)
                log_msg.append("mitmimage: client initiated with new access key.")
        if "mitmimage_config" in updates and ctx.options.mitmimage_config:
            self.load_config(os.path.expanduser("ctx.options.mitmimage_config"))
        if "mitmimage_remove_view" in updates:
            self.remove_view_enable = ctx.options.mitmimage_remove_view
            log_msg.append("mitmimage: remove view: {}.".format(self.remove_view_enable))
        if "mitmimage_debug" in updates:
            if ctx.options.mitmimage_debug:
                self.logger.setLevel(logging.DEBUG)
                self.logger.handlers[0].setLevel(logging.DEBUG)
            else:
                self.logger.setLevel(logging.INFO)
                self.logger.handlers[0].setLevel(logging.INFO)
            log_msg.append("mitmimage: log level: {}.".format(self.logger.level))
        if "mitmimage_log_file" in updates and ctx.options.mitmimage_log_file:
            self.set_log_path(os.path.expanduser(ctx.options.mitmimage_log_file))
        if log_msg:
            if self.ctx_log:
                list(map(ctx.log, log_msg))
            else:
                list(map(self.logger.info, log_msg))

    def get_url_filename(self, url: str) -> Optional[str]:
        """Get url filename.

        >>> MitmImage().get_url_filename('http://example.com/1.jpg')
        '1'
        """
        url_filename = None
        try:
            url_filename = unquote_plus(Path(urlparse(url).path).stem)
            if not url_filename:
                return None
            for item in self.config.get("block_url_filename_regex", []):
                if re.match(item[0], url):  # pragma: no cover
                    self.logger.debug(
                        {
                            LogKey.KEY.value: "skip filename",
                            LogKey.MESSAGE.value: item[1],
                            LogKey.URL.value: url,
                        }
                    )
                    return None
        except Exception as err:  # pragma: no cover
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
        ...     'add_url', {
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
                if new_url == url:  # pragma: no cover
                    continue
                url_sets.append((new_url, rs.page_name))
                log_msg = {LogKey.ORIGINAL.value: url, LogKey.TARGET.value: new_url}
                if rs.log_flag:  # pragma: no cover
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
                args = (
                    "add_url",
                    kwargs,
                )
                self.client_queue.put_nowait(args)

    async def client_worker(self):  # pragma: no cover
        while True:
            # Get a "work item" out of the queue.
            try:
                cmd, kwargs = await self.client_queue.get()
                async with self.client_lock:
                    res = getattr(self.client, cmd)(**kwargs)
                    self.logger.debug(
                        {LogKey.MESSAGE.value: "cmd:{}".format(cmd), "kwargs": kwargs, "res": res}
                    )
            except ConnectionError as err:
                self.logger.debug(str(err), exc_info=True)
                self.logger.error({LogKey.MESSAGE.value: "cmd:{}".format(cmd), "kwargs": kwargs})
            except Exception as err:
                self.logger.exception(str(err))
            # Notify the queue that the "work item" has been processed.
            self.client_queue.task_done()

    async def post_upload_worker(self):  # pragma: no cover
        while True:
            try:
                # Get a "work item" out of the queue.
                url, upload_resp, referer = await self.post_upload_queue.get()
                hash_ = None
                if upload_resp:
                    hash_ = upload_resp.get("hash", None)
                    self.client_queue.put_nowait(
                        (
                            "associate_url",
                            {
                                "hashes": [
                                    upload_resp["hash"],
                                ],
                                "add": [url],
                            },
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
                kwargs: Dict[str, Any] = {"page_name": "mitmimage", "url": url}
                if tags:
                    kwargs["service_names_to_additional_tags"] = {"my tags": tags}
                    if hash_:
                        self.client_queue.put_nowait(
                            (
                                "add_tags",
                                {
                                    "hashes": [hash_],
                                    "service_to_action_to_tags": {"my tags": {TagAction.Add: tags}},
                                },
                            )
                        )
                self.client_queue.put_nowait(("add_url", kwargs))
            except Exception as err:
                self.logger.exception(str(err))
            # Notify the queue that the "work item" has been processed.
            self.post_upload_queue.task_done()

    async def upload_worker(self):  # pragma: no cover
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
                elif status in [ImportStatus.Failed, ImportStatus.Vetoed, 8] and hash_:
                    self.url_data[url].add(hash_)
                    self.hash_data[hash_] = status
                else:
                    self.logger.debug(upload_resp)
                log_msg = {LogKey.STATUS.value: status, LogKey.URL.value: url}
                if self.logger.level == logging.DEBUG:
                    log_msg.update(
                        {
                            LogKey.HASH.value: hash_,
                            "note": upload_resp.get("note", None),
                        }
                    )
                    self.logger.debug(log_msg)
                else:
                    self.logger.info(log_msg)
            except ConnectionError as err:
                self.logger.debug(str(err), exc_info=True)
                self.logger.error(
                    {
                        LogKey.MESSAGE.value: "ConnectionError",
                        LogKey.URL.value: url,
                    }
                )
            except Exception as err:
                self.logger.exception(str(err))
            self.upload_queue.task_done()

    def check_request_flow(self, flow: http.HTTPFlow) -> bool:
        """Check request flow and determine if the flow need to be skipped."""
        url: str = flow.request.pretty_url
        match = first_true(self.host_block_regex, pred=lambda x: x.match(flow.request.pretty_host))
        if match:
            self.logger.debug({LogKey.URL.value: url, LogKey.KEY.value: "host block"})
            return True
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
            return True
        return False

    @concurrent
    def request(self, flow: http.HTTPFlow):
        try:
            url: str = flow.request.pretty_url
            self.add_additional_url(url)
            if self.check_request_flow(flow):
                self.skip_flow.add(flow.id)
                self.logger.debug(
                    {
                        LogKey.URL.value: url,
                        LogKey.MESSAGE.value: "flow id:{}".format(flow.id),
                    }
                )
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
                    7,
                    8,
                ]:
                    return
                redirect = True
                if not redirect:
                    try:
                        file_data = self.client.get_file(hash_=hash_)
                    except APIError as err:
                        self.logger.error(
                            {
                                LogKey.HASH.value: hash_,
                                LogKey.MESSAGE.value: "{}:{}".format(type(err).__name__, err),
                                LogKey.STATUS.value: status,
                                LogKey.URL.value: url,
                            }
                        )
                        return
                    #  NOTE http.Response.make used on mitmproxy v'7.0.0.dev'
                    make = http.HTTPResponse.make if hasattr(http, "HTTPResponse") else http.Response.make  # type: ignore
                    flow.response = make(
                        content=file_data.content,
                        headers=dict(file_data.headers),
                    )
                else:
                    src_url = self.client._api_url + self.client._FILE_ROUTE
                    params = {'hash': hash_, 'Hydrus-Client-API-Access-Key': self.client._access_key}
                    url_parts = list(urlparse(src_url))
                    query = dict(parse_qsl(url_parts[4]))
                    query.update(params)
                    url_parts[4] = urlencode(query)
                    flow.request.url = urlunparse(url_parts)
                    # NOTE skip to not process file from hydrus
                    self.skip_flow.add(flow.id)
                if url not in self.cached_urls:
                    self.cached_urls.add(url)
                self.post_upload_queue.put_nowait(
                    (url, None, flow.request.headers.get("referer", None))
                )
                self.logger.info({LogKey.URL.value: url, LogKey.MESSAGE.value: "add and cached"})
            else:
                self.logger.debug(
                    {
                        "hash count": len(hashes),
                        "url hash": hashes,
                        LogKey.URL.value: url,
                    }
                )
        except ConnectionError as err:
            self.logger.debug(str(err), exc_info=True)
            self.logger.error(
                {
                    LogKey.MESSAGE.value: "ConnectionError",
                    LogKey.URL.value: url,
                }
            )
        except Exception as err:
            self.logger.exception(str(err))

    def check_response_flow(self, flow: http.HTTPFlow) -> bool:
        """Check response flow.

        Result will determine:
        - does flow need to be removed
        - does request need be processed"""
        url = flow.request.pretty_url
        if flow.id in self.skip_flow:
            self.skip_flow.remove(flow.id)
            self.logger.debug(
                {
                    LogKey.URL.value: url,
                    LogKey.MESSAGE.value: "skip flow id:{}".format(flow.id),
                }
            )
            return True
        # skip when it is cached
        if url in self.cached_urls:
            return True
        if flow.response is None:
            return True
        mimetype = None
        if flow.response.content is not None:
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
            return True
        return False

    @concurrent
    def response(self, flow: http.HTTPFlow) -> None:
        """Handle response."""
        try:
            if self.check_response_flow(flow):
                self.remove_from_view(flow)
                return
            url: str = flow.request.pretty_url
            hashes = self.get_hashes(url, "on_empty")
            single_hash_data = None
            if hashes and len(hashes) == 1:
                single_hash_data = self.hash_data.get(next(iter(hashes)), None)
            if not hashes or single_hash_data == ImportStatus.Importable:
                self.upload_queue.put_nowait(flow)
            elif single_hash_data in [
                ImportStatus.Failed,
                ImportStatus.PreviouslyDeleted,
                ImportStatus.Vetoed,
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
            self.logger.debug(str(err), exc_info=True)
            self.logger.error(
                {
                    LogKey.MESSAGE.value: "ConnectionError",
                    LogKey.URL.value: url,
                }
            )
        except Exception as err:
            self.logger.exception(str(err))

    def error(self, flow: http.HTTPFlow):
        """An HTTP error has occurred, e.g. invalid server responses, or
        interrupted connections. This is distinct from a valid server HTTP
        error response, which is simply a response with an HTTP error code.
        """
        self.remove_from_view(flow)  # pragma: no cover

    @property
    def ctx_log(self):
        return hasattr(ctx, "log")

    # command

    @command.command("mitmimage.log_hello")
    def log_hello(self):  # pragma: no cover
        ctx.log.info("mitmimage: hello")

    @command.command("mitmimage.clear_data")
    def clear_data(self) -> None:
        self.url_data: Dict[str, Set[str]] = defaultdict(set)
        self.hash_data: Dict[str, ImportStatus] = {}
        if self.ctx_log:  # pragma: no cover
            ctx.log.info("mitmimage: data cleared")

    @command.command("mitmimage.ipdb")
    def ipdb(self, flows: Sequence[Flow] = None) -> None:  # pragma: no cover
        import ipdb

        ipdb.set_trace()

    @command.command("mitmimage.remove_flow_with_data")
    def remove_flow_with_data(self):  # pragma: no cover
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
            try:
                resp = self.upload(flow)
                self.client_queue.put_nowait(("add_url", {"url": url, "page_name": "mitmimage"}))
                resp_history.append(resp)
                if remove and resp is not None:
                    self.remove_from_view(flow)
            except Exception as err:
                self.logger.exception(str(err))
        data = [x["status"] for x in resp_history if x is not None]
        for obj in [self.logger, ctx.log]:
            obj.info(Counter(data) if data else "upload finished")
