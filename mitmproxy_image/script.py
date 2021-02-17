#!/usr/bin/env python
# -*- coding: utf-8 -*-
import asyncio
import cgi
import functools
import io
import logging
import mimetypes
import os
import re
import typing
from collections import Counter, defaultdict
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Set, Union
from urllib.parse import unquote_plus, urlparse

import yaml
from hydrus import APIError, Client, ConnectionError, ImportStatus
from mitmproxy import command, ctx, http
from mitmproxy.flow import Flow
from mitmproxy.script import concurrent


def get_mimetype(
    flow: Optional[http.HTTPFlow] = None, url: Optional[str] = None
) -> Optional[str]:
    """Get mimetype from flow or url.

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


class MitmImage:

    url_data: Dict[str, List[str]]
    normalised_url_data: Dict[str, str]
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
        # logger
        logger = logging.getLogger("mitmimage")
        logger.setLevel(logging.INFO)
        # create file handler
        fh = logging.FileHandler(os.path.expanduser("~/mitmimage.log"))
        fh.setLevel(logging.INFO)
        fh.setFormatter(
            logging.Formatter("%(levelname).1s:%(funcName)s:%(lineno)s:%(message)s")
        )
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
        self.cached_urls = {}
        self.page_name = "mitmimage"
        self.additional_page_name = "mitmimage_plus"

    def is_valid_content_type(
        self, flow: Optional[http.HTTPFlow] = None, url: Optional[str] = None
    ) -> bool:
        mimetype = get_mimetype(flow, url)
        if not mimetype:
            return False
        try:
            maintype, subtype = mimetype.lower().split("/")
            subtype = subtype.lower()
        except ValueError:
            self.logger.info(
                "unknown mimetype:{}\nurl:{}\nflow:{}".format(mimetype, url, flow)
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
        hashes = self.url_data.get(url, {})
        if hashes and from_hydrus == "on_empty":
            return hashes
        huf_resp = self.client.get_url_files(url)
        # ufs = get_url_status
        for ufs in huf_resp["url_file_statuses"]:
            self.url_data[url].add(ufs["hash"])
            self.hash_data[ufs["hash"]] = ufs["status"]
        hashes = self.url_data[url]
        return hashes

    def upload(self, flow: Union[http.HTTPFlow, Flow]) -> Optional[Dict[str, str]]:
        url = flow.request.pretty_url  # type: ignore
        response = flow.response  # type: ignore
        if response is None:
            self.logger.debug("no response url:{}".format(url))
            return None
        content = response.get_content()
        if content is None:
            self.logger.debug("no content url:{}".format(url))
            return None
        # upload file
        upload_resp = self.client.add_file(io.BytesIO(content))
        self.logger.info("{},{}".format(upload_resp["status"], url))
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
                if view_filter:
                    ctx.options.view_filter = view_filter
                    ctx.log.info("view_filter: {}".format(view_filter))
                ctx.log.info(
                    "mitmimage: load {} block regex.".format(
                        len(self.config.get("block_regex", []))
                    )
                )
                ctx.log.info(
                    "mitmimage: load {} url filename block regex.".format(
                        len(self.config.get("block_url_filename_regex", []))
                    )
                )
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
            typespec=typing.Optional[str],
            default=self.default_config_path,
            help="mitmimage config file",
        )

    def configure(self, updates):
        if "hydrus_access_key" in updates:
            hydrus_access_key = ctx.options.hydrus_access_key
            if hydrus_access_key and hydrus_access_key != self.client._access_key:
                self.client = Client(hydrus_access_key)
                ctx.log.info("mitmimage: client initiated with new access key.")
        if "mitmimage_config" in updates and ctx.options.mitmimage_config:
            self.load_config(ctx.options.mitmimage_config)
            self.get_url_filename.cache_clear()
            self.skip_url.cache_clear()

    @functools.lru_cache(1024)
    def get_url_filename(self, url: str, max_len: int = 120):
        """Get url filename.

        >>> MitmImage().get_url_filename('http://example.com/1.jpg')
        '1'
        """
        url_filename = None
        try:
            url_filename = unquote_plus(Path(urlparse(url).path).stem)
            for item in self.config.get("block_url_filename_regex", []):
                if url_filename and re.match(item[0], url_filename.lower()):
                    self.logger.info("rskip filename:{},{}".format(item[1], url))
                    url_filename = None
                if url_filename and len(url_filename) > max_len:
                    self.logger.info(
                        "url filename too long:{}\nurl:{}".format(
                            url_filename[:max_len], url
                        )
                    )
                    url_filename = None
        except Exception as err:
            self.logger.exception(err.message if hasattr(err, "message") else str(err))
        return url_filename

    @functools.lru_cache(1024)
    def skip_url(self, url):
        for item in self.config.get("block_regex", []):
            if re.match(item[0], url):
                try:
                    item[2]
                except IndexError:
                    item.append(False)
                return item

    def add_additional_url(self, url: str):
        """add additional url.

        >>> from unittest import mock
        >>> obj = MitmImage()
        >>> obj.config = {'add_url_regex': [[
        ...     r'https://example.com/(.*)',
        ...     'https://example.com/sub/{0}']]}
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
        regex_sets = self.config.get("add_url_regex", [])
        for regex_set in regex_sets:
            regex, url_fmt = regex_set[:2]
            log_flag = regex_set[2] if 2 < len(regex_set) else False
            page_name = (
                regex_set[4] if 4 < len(regex_set) else self.additional_page_name
            )
            match = re.match(regex, url)
            if match and match.groups():
                new_url = url_fmt.format(*match.groups())
                url_sets.append((new_url, page_name))
                log_msg = "original:{}\ntarget:{}".format(url, new_url)
                log_func = self.logger.info if log_flag else self.logger.debug
                log_func(log_msg)
        if url_sets:
            for (new_url, page_name) in url_sets:
                kwargs = {"page_name": page_name, "url": new_url}
                filename = self.get_url_filename(new_url)
                if filename:
                    kwargs["service_names_to_additional_tags"] = {
                        "my tags": ["filename:{}".format(filename)]
                    }
                args = ("add_url", [], kwargs)
                self.client_queue.put_nowait(args)
                self.logger.info(new_url)

    def get_normalised_url(self, url: str) -> Optional[str]:
        if url in self.normalised_url_data:
            return self.normalised_url_data[url]
        normalised_url = self.client.get_url_info(url).get("normalised_url", None)
        if normalised_url is not None:
            self.normalised_url_data[url] = normalised_url
        return normalised_url

    async def client_worker(self):
        queue = self.client_queue
        while True:
            # Get a "work item" out of the queue.
            try:
                cmd, args, kwargs = await queue.get()
                self.logger.debug("cmd:{},args:{},kwargs:{}".format(cmd, args, kwargs))
                async with self.client_lock:
                    getattr(self.client, cmd)(*args, **kwargs)
            except ConnectionError as err:
                self.logger.info(err.message if hasattr(err, "message") else str(err))
            except Exception as err:
                self.logger.error(
                    err.message if hasattr(err, "message") else str(err), exc_info=True
                )
            # Notify the queue that the "work item" has been processed.
            queue.task_done()

    async def post_upload_worker(self):
        # compatibility
        queue = self.post_upload_queue
        get_normalised_url_func = self.get_normalised_url
        url_data = self.url_data
        hash_data = self.hash_data
        get_url_filename_func = self.get_url_filename
        while True:
            try:
                # Get a "work item" out of the queue.
                url, upload_resp, referer = await queue.get()
                normalised_url = get_normalised_url_func(url)
                if upload_resp:
                    self.client_queue.put_nowait(
                        (
                            "associate_url",
                            [
                                [
                                    upload_resp["hash"],
                                ],
                                [normalised_url],
                            ],
                            {},
                        )
                    )
                    # update data
                    url_data[normalised_url].append(upload_resp["hash"])
                    hash_data[upload_resp["hash"]] = upload_resp["status"]
                tags = []
                url_filename = get_url_filename_func(url)
                if url_filename:
                    tags.append("filename:{}".format(url_filename))
                if referer:
                    tags.append("referer:{}".format(referer))
                kwargs: Dict[str, Any] = {"page_name": "mitmimage"}
                if tags:
                    kwargs["service_names_to_additional_tags"] = {"my tags": tags}
                self.client_queue.put_nowait(("add_url", [normalised_url], kwargs))
            except Exception as err:
                self.logger.error(
                    err.message if hasattr(err, "message") else str(err), exc_info=True
                )
            # Notify the queue that the "work item" has been processed.
            queue.task_done()

    async def upload_worker(self):
        client = self.client
        queue = self.upload_queue
        logger = self.logger
        post_upload_queue = self.post_upload_queue
        client_lock = self.client_lock
        while True:
            try:
                # Get a "work item" out of the queue.
                flow = await queue.get()
                url = flow.request.pretty_url  # type: ignore
                response = flow.response  # type: ignore
                if response is None:
                    logger.debug("no response url:{}".format(url))
                    queue.task_done()
                    return
                content = response.get_content()
                if content is None:
                    logger.debug("no content url:{}".format(url))
                    queue.task_done()
                    return
                # upload file
                async with client_lock:
                    upload_resp = client.add_file(io.BytesIO(content))
                referer = flow.request.headers.get("referer", None)
                if upload_resp["status"] not in [
                    ImportStatus.Failed,
                    ImportStatus.PreviouslyDeleted,
                ]:
                    post_upload_queue.put_nowait((url, upload_resp, referer))
                logger.info("{},{}".format(upload_resp["status"], url))
            except ConnectionError as err:
                self.logger.error("{}:{}\nurl:{}".format(type(err).__name__, err, url))
            except Exception as err:
                self.logger.error(
                    err.message if hasattr(err, "message") else str(err), exc_info=True
                )
            queue.task_done()

    @concurrent
    def request(self, flow: http.HTTPFlow):
        try:
            url: str = flow.request.pretty_url
            self.add_additional_url(url)
            if flow.request.method == "POST":
                self.remove_from_view(flow=flow)
                return
            match_regex = self.skip_url(url)
            if match_regex:
                msg = "rskip url:{},{}".format(match_regex[1], url)
                self.logger.debug(msg)
                self.remove_from_view(flow=flow)
                return
            hashes = []
            hashes = self.get_hashes(url, "always")
            if not hashes and not self.is_valid_content_type(url=url):
                return
            if len(hashes) == 1:
                hash_: str = hashes[0]
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
                        "get file error:{}:{}\nurl:{}\nhash:{},{}".format(
                            type(err).__name__, err, url, status, hash_
                        )
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
                self.logger.info("add and cached:{}".format(url))
                self.remove_from_view(flow=flow)
            elif hashes:
                self.logger.debug(
                    "hash count:{},{}\nurl hash:\n{}".format(
                        len(hashes), url, "\n".join(hashes)
                    )
                )
            else:
                msg = "no hash:{}".format(url)
                self.logger.debug(msg)
        except ConnectionError as err:
            self.logger.error("{}:{}\nurl:{}".format(type(err).__name__, err, url))
        except Exception as err:
            self.logger.exception(str(err))

    @concurrent
    def response(self, flow: http.HTTPFlow) -> None:
        """Handle response."""
        try:
            url = flow.request.pretty_url
            match_regex = self.skip_url(url)
            if match_regex:
                msg = "rskip url:{},{}".format(match_regex[1], url)
                self.logger.debug(msg)
                self.remove_from_view(flow)
                return
            if get_mimetype(flow=flow) is None:
                self.logger.debug("No mimetype:\n{}".format(vars(flow.response)))
            elif not self.is_valid_content_type(flow):
                self.remove_from_view(flow)
                return
            normalised_url = self.get_normalised_url(url)
            # skip when it is cached
            if normalised_url in self.cached_urls:
                self.remove_from_view(flow)
                return
            hashes = self.get_hashes(url, "on_empty")
            single_hash_data = None
            if hashes and len(hashes) == 1:
                single_hash_data = self.hash_data.get(hashes[0], None)
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
                hashes_status = [
                    "{}:{}".format(self.hash_data.get(x, None), x) for x in hashes
                ]
                self.logger.info("add:{}\n{}".format(url, "\n".join(hashes_status)))
            self.remove_from_view(flow)
        except ConnectionError as err:
            self.logger.error("{}:{}\nurl:{}".format(type(err).__name__, err, url))
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
    def ipdb(self, flows: typing.Sequence[Flow] = None) -> None:  # pragma: no cover
        import ipdb

        ipdb.set_trace()

    @command.command("mitmimage.log_info")
    def log_info(self):
        ctx.log.info(
            "cache:{},{}\nurl:{}".format(
                "get_url_files",
                self.get_url_files.cache_info(),
                len(list(self.data.keys())),
            )
        )

    @command.command("mitmimage.remove_flow_with_data")
    def remove_flow_with_data(self):
        items = filter(
            lambda item: item[1].response and item[1].response.content is not None,
            self.view._store.items(),
        )
        self.view.remove([x[1] for x in items])

    @command.command("mitmimage.toggle_debug")
    def toggle_debug(self):
        if self.logger.level == logging.DEBUG:
            self.logger.setLevel(logging.INFO)
            self.logger.handlers[0].setLevel(logging.INFO)
        else:
            self.logger.setLevel(logging.DEBUG)
            self.logger.handlers[0].setLevel(logging.DEBUG)
        ctx.log.info("log level:{}".format(self.logger.level))

    @command.command("mitmimage.upload_flow")
    def upload_flow(self, flows: typing.Sequence[Flow], remove: bool = False) -> None:
        logger = SimpleNamespace(
            debug=lambda msg: list(
                map(lambda func_log: func_log.debug(msg), [self.logger, ctx.log])
            ),
            info=lambda msg: list(
                map(lambda func_log: func_log.info(msg), [self.logger, ctx.log])
            ),
        )
        resp_history = []
        for flow in flows:
            url = flow.request.pretty_url  # type: ignore
            self.add_additional_url(url)
            match_regex = self.skip_url(url)
            if match_regex:
                msg = "rskip url:{},{}".format(match_regex[1], url)
                self.logger.debug(msg)
                self.remove_from_view(flow)
                continue
            resp = self.upload(flow)
            self.client_queue.put_nowait(("add_url", [url], {"page_name": "mitmimage"}))
            resp_history.append(resp)
            if remove and resp is not None:
                self.remove_from_view(flow)
        data = [x["status"] for x in resp_history if x is not None]
        if data:
            logger.info(Counter(data))
        else:
            logger.info("upload finished")
