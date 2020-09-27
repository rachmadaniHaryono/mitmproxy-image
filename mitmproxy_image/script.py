#!/usr/bin/env python
# -*- coding: utf-8 -*-
import cgi
import functools
import io
import logging
import mimetypes
import re
import threading
import typing
from collections import Counter, defaultdict
from functools import partial
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest import mock
from urllib.parse import urlparse

from hydrus import Client
from mitmproxy import command, ctx, http
from mitmproxy.flow import Flow
from mitmproxy.script import concurrent


class MitmImage:

    def __init__(self):
        self.data = {}
        self.lock = threading.Lock()
        self.logger = logging.getLogger()
        self.default_access_key = \
            '918efdc1d28ae710b46fc814ee818100a102786140ede877db94cedf3d733cc1'
        self.client = Client(self.default_access_key)
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
        self.block_regex = [
            [
                r'https:\/.yt3.ggpht.com\/a\/.+=s48-c-k-c0xffffffff-no-rj-mo',
                'yt3.ggpht.com a48'],
            [
                r'https:\/.yt3.ggpht.com\/a\/.+=s32-c-k-c0x00ffffff-no-rj-mo',
                'yt3.ggpht.com a32'],
            [
                r'https:\/.yt3.ggpht.com\/a-\/.+=s48-mo-c-c0xffffffff-rj-k-no',
                'yt3.ggpht.com a-48'],
            [
                r'https:\/.yt3.ggpht.com\/.+\/AAAAAAAAAAI\/AAAAAAAAAAA\/.+\/s32-c-k-no-mo-rj-c0xffffff\/photo.jpg',  # NOQA
                'yt3.ggpht.com 32']
        ]

    # classmethod

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
        if 'Content-type' not in flow.response.data.headers:
            return False
        content_type = flow.response.data.headers['Content-type']
        mimetype = cgi.parse_header(content_type)[0]
        try:
            maintype, subtype = mimetype.lower().split('/')
        except ValueError:
            if logger:
                logger.info('unknown mimetype:{}'.format(mimetype))
            return False
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
        if view is not None and f in view._view:
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
            logger: Optional[Any] = None,
            associated_url: Optional[str] = None
    ) -> Optional[Dict[str, str]]:
        url = flow.request.pretty_url
        try:
            url_filename = Path(urlparse(url).path).stem
        except Exception:
            url_filename = None
        if flow.response is None:
            if logger:
                logger.debug('no response url:{}'.format(url))
            return None
        content = flow.response.get_content()
        if content is None:
            if logger:
                logger.debug('no content url:{}'.format(url))
            return None
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
        if url_filename:
            client.add_url(
                associated_url, page_name='mitmimage',
                service_names_to_tags={
                    'my tags': 'filename:{}'.format(url_filename)
                })
        else:
            client.add_url(associated_url, page_name='mitmimage')
        return upload_resp

    # method

    @functools.lru_cache(1024)
    def get_url_files(self, url: str):
        return self.client.get_url_files(url)

    # mitmproxy add on class' method

    def load(self, loader):
        loader.add_option(
            name="hydrus_access_key",
            typespec=str,
            default=self.default_access_key,
            help="Hydrus Access Key",
        )

    def configure(self, updates):
        if "hydrus_access_key" in updates:
            if not ctx.options.hydrus_access_key:
                ctx.log.info('mitmimage: client is initiated with default access key.')
            else:
                ctx.log.info('mitmimage: client initiated.')

    @concurrent
    def request(self, flow: http.HTTPFlow):
        url = flow.request.pretty_url
        remove_from_view = partial(self.remove_from_view, view=self.view)
        for item in self.block_regex:
            if re.match(item[0], url):
                self.logger.info('regex skip url:{},{}'.format(item[1], url))
                remove_from_view(flow=flow)
                return
        mimetype: Optional[str] = None
        valid_content_type = False
        try:
            mimetype = cgi.parse_header(mimetypes.guess_type(url)[0])[0]
            mock_flow = mock.Mock()
            mock_flow.response.data.headers = {'Content-type': mimetype}
            valid_content_type = \
                self.is_valid_content_type(mock_flow, self.logger)
        except Exception:
            pass
        if ((url not in self.data) or (not self.data[url]['hydrus'])) and not mimetype:
            return
        elif not valid_content_type:
            self.logger.debug('invalid guessed mimetype:{},{}'.format(mimetype, url))
            return
        else:
            self.logger.debug('valid guessed mimetype:{},{}'.format(mimetype, url))
            if url not in self.data:
                self.data[url] = {'hydrus': None}
            self.data[url]['hydrus'] = self.get_url_files(url)
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
        remove_from_view(flow=flow)

    @concurrent
    def response(self, flow: http.HTTPFlow) -> None:
        """Handle response."""
        if (not flow.response) or (
                not self.is_valid_content_type(flow, logger=self.logger)):
            return
        # hydrus url files response
        url = flow.request.pretty_url
        try:
            url_filename = Path(urlparse(url).path).stem
        except Exception:
            url_filename = None
        remove_from_view = partial(self.remove_from_view, view=self.view)
        for item in self.block_regex:
            if re.match(item[0], url):
                self.logger.info('regex skip url:{},{}'.format(item[1], url))
                remove_from_view(flow=flow)
                return
        with self.lock:
            if url not in self.data:
                self.data[url] = {'hydrus': None}
            url_data = self.data[url].get('hydrus', None)
            if not url_data:
                #  huf = hydrus url files
                huf_resp = self.get_url_files(url)
                self.data[url]['hydrus'] = url_data = huf_resp
                url_file_statuses = huf_resp.get('url_file_statuses', None)
                if (url_file_statuses and self.show_downloaded_url and
                        any(x['status'] == 2 for x in url_file_statuses)):
                    if url_filename:
                        self.client.add_url(url, page_name='mitmimage')
                    else:
                        self.client.add_url(
                            url,
                            page_name='mitmimage',
                            service_names_to_tags={
                                'my tags': 'filename:{}'.format(url_filename)
                            })
            if url_data.get('url_file_statuses', None):
                remove_from_view(flow=flow)
                return
            # upload file
            upload_resp = self.upload(
                flow, self.client, self.logger,
                url_data.get('normalised_url', None))
            # remove from view
            remove_from_view(flow=flow)
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

    @command.command('mitmimage.ipdb_flow')
    def ipdb(self, flows: Optional[typing.Sequence[Flow]] = None) -> None:
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
    def upload_flow(
        self,
        flows: typing.Sequence[Flow],
        remove: bool = False
    ) -> None:
        cls_logger = self.logger

        class CustomLogger:

            def debug(self, msg):
                cls_logger.debug(msg)
                ctx.log.debug(msg)

            def info(self, msg):
                cls_logger.info(msg)
                ctx.log.info(msg)

        logger = CustomLogger()
        resp_history = []
        for flow in flows:
            resp = self.upload(flow, self.client, logger)
            resp_history.append(resp)
            if remove and resp is not None:
                self.remove_from_view(self.view, flow)
        logger.info(Counter([
            x['status'] for x in resp_history if x is not None]))


addons = [MitmImage()]
