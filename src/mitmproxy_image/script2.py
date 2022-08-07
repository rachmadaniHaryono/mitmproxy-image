#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
resources:

- async https://docs.mitmproxy.org/stable/addons-examples/#nonblocking
- basic https://docs.mitmproxy.org/stable/addons-overview/#anatomy-of-an-addon
- queue https://github.com/mitmproxy/mitmproxy/blob/af5be0b92817eebb534e05fa0cc45127a70fa113/examples/contrib/jsondump.py
"""
import collections
import copy
import io
import os
import re
import traceback
import typing as T
from collections import abc
from pathlib import Path
from queue import Queue
from threading import Thread
from urllib.parse import parse_qsl, unquote_plus, urlencode, urlparse, urlunparse

import hydrus_api
import yaml
from mitmproxy import command, ctx, flowfilter
from mitmproxy.flow import Flow
from more_itertools import first_true, nth
from PIL import Image


def get_referer_tag(flow) -> str:
    referer = flow.request.headers.get("referer", None)
    if referer:
        return f"referer:{referer}"
    return ""


def get_url_filename(url: str) -> str:
    """Get url filename.

    >>> get_url_filename('http://example.com/1.jpg')
    '1'
    """
    url_filename = None
    try:
        url_filename = unquote_plus(Path(urlparse(url).path).stem)
    except Exception as err:
        ctx.log.error(f"client: {err}\n{traceback.format_exc()}")
    if url_filename:
        return f"filename:{url_filename}"
    return ""


def get_redirect_url(hash_: str, client: hydrus_api.Client) -> str:
    """Get redirect url.
    >>> from types import SimpleNamespace
    >>> get_redirect_url("1234", SimpleNamespace(
    ...  _api_url="https://127.0.0.1", _GET_FILE_PATH="/get_files/file", _access_key="5678"))
    'https://127.0.0.1/get_files/file?hash=1234&Hydrus-Client-API-Access-Key=5678'
    """
    api_url = client._api_url if hasattr(client, "_api_url") else client.api_url
    src_url = api_url + client._GET_FILE_PATH
    params = {"hash": hash_, "Hydrus-Client-API-Access-Key": client.access_key}
    url_parts = list(urlparse(src_url))
    query = dict(parse_qsl(url_parts[4]))
    query.update(params)
    url_parts[4] = urlencode(query)
    return urlunparse(url_parts)


def get_url_filename_tag(url):
    url_filename = unquote_plus(Path(urlparse(url).path).stem)
    if not url_filename:
        return ""
    return f"filename:{url_filename}"


def add_and_tag_files(
    paths_or_files: abc.Iterable[T.Union[str, os.PathLike, hydrus_api.BinaryFileLike]],
    tags: abc.Iterable[str],
    client: hydrus_api.Client,
    service_names: T.Optional[abc.Iterable[str]] = None,
    service_keys: T.Optional[abc.Iterable[str]] = None,
) -> list[dict[str, T.Any]]:
    """Convenience method to add and tag multiple files at the same time.

    If service_names and service_keys aren't specified, the default service name "my tags" will be used. If a file
    already exists in Hydrus, it will also be tagged.

    Returns:
        list[dict[str, T.Any]]: Returns results of all `Client.add_file()` calls, matching the order of the
        paths_or_files iterable
    """
    if service_names is None and service_keys is None:
        service_names = ("my tags",)

    results = []
    hashes = set()
    for path_or_file in paths_or_files:
        result = client.add_file(path_or_file)
        results.append(result)
        if result["status"] != hydrus_api.ImportStatus.FAILED:
            hashes.add(result["hash"])

    service_names_to_tags = (
        {name: tags for name in service_names} if service_names is not None else None
    )
    service_keys_to_tags = (
        {key: tags for key in service_keys} if service_keys is not None else None
    )
    # Ignore type, we know that hashes only contains strings
    if hashes and tags:
        client.add_tags(hashes, service_names_to_tags=service_names_to_tags, service_keys_to_tags=service_keys_to_tags)  # type: ignore
    return results


class MitmImage:
    def __init__(self):
        self.client_queue = Queue()
        access_key = "4bd08d98f1e566a5ec78afe42c070d303b5340fd47a814782f30b43316c2cecf"
        self.client = hydrus_api.Client(access_key)
        self.num = 0
        self.base_filter = f"~m GET & !(~websocket | ~d '{self.client.api_url}')"
        self.url_hash_dict = {}
        self.hash_status_dict = {}
        self.hash_tags_dict = collections.defaultdict(set)
        self.config = {}

    def client_worker(self):
        while True:
            item = self.client_queue.get()
            action = item.get("action")
            try:
                if action == "upload":
                    ctx.log.warn("unmaintained upload action is executed")
                    upload_resp = self.client.add_file(item["content"])
                    url = item["url"]
                    hash_ = upload_resp["hash"]
                    status = upload_resp["status"]
                    self.hash_status_dict[hash_] = status
                    note = upload_resp.pop("note", None)
                    ctx.log.info(
                        "\n".join(
                            [
                                f"upload: {url}",
                                str(upload_resp),
                                f"note: {note}" if note else "",
                            ]
                        ).strip()
                    )
                    if url not in self.url_hash_dict:
                        self.url_hash_dict[url] = hash_
                        self.client_queue.put(
                            {
                                "urls_to_add": [url],
                                "hashes": [hash_],
                                "action": "associate_url",
                            }
                        )
                    if status in (
                        hydrus_api.ImportStatus.SUCCESS,
                        hydrus_api.ImportStatus.EXISTS,
                    ):
                        self.client_queue.put(
                            {
                                "action": "add_url",
                                "url": url,
                                "destination_page_name": "mitmimage",
                            }
                        )
                elif action in (
                    "associate_url",
                    "add_url",
                    "add_tags",
                    "add_and_tag_files",
                ):

                    exclude_keys = (
                        ("action", "urls")
                        if action == "add_and_tag_files"
                        else ("action",)
                    )
                    if action == "add_and_tag_files":
                        item["client"] = self.client
                        resp = add_and_tag_files(
                            **{k: v for k, v in item.items() if k not in exclude_keys}
                        )
                    else:
                        resp = getattr(self.client, action)(
                            **{k: v for k, v in item.items() if k not in exclude_keys}
                        )
                    if action == "add_and_tag_files":
                        urls = item.get("urls")
                        # associate_url
                        if urls and (
                            associate_hashes := [
                                upload_resp["hash"]
                                for upload_resp in resp
                                if upload_resp["status"]
                                in (
                                    hydrus_api.ImportStatus.EXISTS,
                                    hydrus_api.ImportStatus.SUCCESS,
                                )
                            ]
                        ):
                            self.client_queue.put(
                                {
                                    "urls_to_add": urls,
                                    "hashes": associate_hashes,
                                    "action": "associate_url",
                                }
                            )
                        # update url_hash_dict
                        if urls:
                            if len(urls) == 1:
                                for upload_resp in resp:
                                    self.url_hash_dict[urls[0]] = upload_resp["hash"]
                            elif len(urls) > 1 and len(resp) == 1:
                                #  handle multi url, single upload_resp
                                for url in urls:
                                    self.url_hash_dict[url] = resp[0]["hash"]
                            else:
                                ctx.log.warn(
                                    "unknown condition when updating url hash dict: "
                                    "urls {} / resp {}\nurls:\n{}\nresp:\n{}".format(
                                        len(urls),
                                        len(resp),
                                        "\n".join(urls),
                                        "\n".join([str(x) for x in resp]),
                                    )
                                )
                        for upload_resp in resp:
                            note = upload_resp.pop("note", None)
                            if (lines := note.splitlines()) and lines[-1].startswith(
                                "hydrus.core.HydrusExceptions.UnsupportedFileException"
                            ):
                                note = lines[-1]
                            ctx.log.info(
                                "\n".join(
                                    [
                                        "add_and_tag_files:\n{}".format(
                                            "\n".join(urls)
                                        ),
                                        str(upload_resp),
                                        f"note: {note}" if note else "",
                                    ]
                                ).strip()
                            )
                            if upload_resp["status"] in (
                                hydrus_api.ImportStatus.EXISTS,
                                hydrus_api.ImportStatus.SUCCESS,
                            ):
                                [
                                    self.client_queue.put(
                                        {
                                            "action": "add_url",
                                            "url": url,
                                            "destination_page_name": "mitmimage",
                                        }
                                    )
                                    for url in urls
                                ]
                            # update hash_tags_dict
                            if item["tags"]:
                                self.hash_tags_dict[upload_resp["hash"]] |= set(
                                    item["tags"]
                                )
                    elif resp:
                        ctx.log.info(f"{action}: {resp}")
                    if action == "add_tags":
                        for hash_ in item.get("hashes", []):
                            if sn_tags := item.get("service_names_to_tags"):
                                self.hash_tags_dict[hash_] |= set(sn_tags["my tags"])

                else:
                    raise ValueError(f"Unknown action: {action}")
            except Exception as err:
                ctx.log.error(f"client: {err}\n{traceback.format_exc()}")
                ctx.log.error(f"item: {item}")
            self.client_queue.task_done()

    def load(self, loader):
        loader.add_option(
            name="mitmimage_config",
            typespec=str,
            default="",
            help="mitmproxy image config",
        )

    def configure(self, updates):
        t = Thread(target=self.client_worker)
        t.daemon = True
        t.start()
        if "mitmimage_config" in updates and ctx.options.mitmimage_config:
            self.config = yaml.safe_load(
                Path(ctx.options.mitmimage_config).expanduser().read_text()
            )
            for key in ("block_regex", "add_url_regex", "block_url_filename_regex"):
                for idx, item in enumerate(self.config[key]):
                    self.config[key][idx][0] = re.compile(self.config[key][idx][0])

    async def request(self, flow):
        url = flow.request.pretty_url
        for item in self.config.get("add_url_regex", []):
            if (match_res := item[0].match(url)) and (groups := match_res.groups()):
                new_url = item[1].format(*groups)
                self.client_queue.put(
                    {
                        "action": "add_url",
                        "url": new_url,
                        "destination_page_name": nth(item, 4, "mitmimage_plus"),
                    }
                )
                ctx.log.debug(f"add_url_regex: {new_url}")
        if not flowfilter.match(self.base_filter, flow):
            return
        if (hash_ := self.url_hash_dict.get(url)) and self.hash_status_dict.get(
            hash_
        ) in (
            hydrus_api.ImportStatus.EXISTS,
            hydrus_api.ImportStatus.SUCCESS,
        ):
            flow.request.url = get_redirect_url(hash_, self.client)

    async def response(self, flow):
        if not flowfilter.match(self.base_filter + ' & ~ts "(image|video)"', flow):
            return
        url = flow.request.pretty_url
        hash_ = self.url_hash_dict.get(url)
        hash_tags = set() if not hash_ else self.hash_tags_dict.get(hash_, set())
        url_filename = get_url_filename_tag(url)
        if url_filename:
            if first_true(
                self.config.get("block_url_filename_regex", []),
                pred=lambda x: x[0].match(url),
            ):
                url_filename = ""
                ctx.log.info(f"url_filename blocked: {url}")
        tags = list(
            {
                x
                for x in (url_filename, get_referer_tag(flow))
                if x and x not in hash_tags
            }
        )
        add_and_tag_files = True
        if hash_:
            import_status = self.hash_status_dict.get(hash_)
            if import_status is None or hydrus_api.ImportStatus.IMPORTABLE:
                pass
            elif import_status in (
                hydrus_api.ImportStatus.EXISTS,
                hydrus_api.ImportStatus.SUCCESS,
            ):
                if tags:
                    self.client_queue.put(
                        {
                            "action": "add_tags",
                            "hashes": [hash_],
                            "service_names_to_tags": {"my tags": tags},
                        }
                    )
                add_and_tag_files = False
            elif import_status in (
                hydrus_api.ImportStatus.PREVIOUSLY_DELETED,
                hydrus_api.ImportStatus.FAILED,
                hydrus_api.ImportStatus.VETOED,
            ):
                add_and_tag_files = False
            else:
                ctx.log.error(f"response import status, url: {url}\nhash: {hash_}")
        if add_and_tag_files and first_true(
            self.config.get("block_regex", []), pred=lambda x: x[0].match(url)
        ):
            add_and_tag_files = False
        bytes_io = io.BytesIO(flow.response.get_content())
        try:
            size = Image.open(copy.copy(bytes_io)).size
            if size[0] < 150 or size[1] < 150:
                add_and_tag_files = False
                ctx.log.debug(f"failed size check {size}: {url}")
        except Exception as err:
            ctx.log.error(f"client: {err}\n{traceback.format_exc()}\nurl: {url}")
        if not add_and_tag_files:
            return
        self.client_queue.put(
            {
                "action": "add_and_tag_files",
                "paths_or_files": [
                    copy.copy(bytes_io),
                ],
                "urls": [url],
                "tags": tags if tags else [],
            }
        )

    def done(self):
        self.client_queue.join()

    @command.command("mitmimage.ipdb")
    def ipdb(self, flows: abc.Sequence[Flow] = None) -> None:  # pragma: no cover
        import ipdb

        ipdb.set_trace()


addons = [MitmImage()]
