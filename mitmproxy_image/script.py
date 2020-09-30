#!/usr/bin/env python
# -*- coding: utf-8 -*-
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
from typing import Any, Dict, List, Optional, Tuple
from unittest import mock
from urllib.parse import urlparse

import yaml
from hydrus import Client, ImportStatus
from mitmproxy import command, ctx, http
from mitmproxy.flow import Flow
from mitmproxy.script import concurrent


class MitmImage:

    def __init__(self):
        self.data = {}
        self.logger = logging.getLogger()
        self.default_access_key = \
            '918efdc1d28ae710b46fc814ee818100a102786140ede877db94cedf3d733cc1'
        self.default_config_path = os.path.expanduser('~/mitmimage.yaml')
        self.client = Client(self.default_access_key)
        logger = logging.getLogger('mitmimage')
        logger.setLevel(logging.DEBUG)
        # create file handler which logs even debug messages
        fh = logging.FileHandler('/home/r3r/mitmimage.log')
        fh.setLevel(logging.DEBUG)
        logger.addHandler(fh)
        self.logger = logger
        master = getattr(ctx, 'master', None)
        self.view = master.addons.get('view') if master else None
        self.config = {}
        self.load_config(self.default_config_path)

    # classmethod

    @classmethod
    def is_valid_content_type(
            cls, flow: http.HTTPFlow,
            logger: Optional[Any] = None,
            mimetype_sets: Optional[List[Tuple[str, str]]] = None
    ) -> bool:
        if 'Content-type' not in flow.response.data.headers:
            return False
        content_type = flow.response.data.headers['Content-type']
        mimetype = cgi.parse_header(content_type)[0]
        try:
            maintype, subtype = mimetype.lower().split('/')
            subtype = subtype.lower()
        except ValueError:
            if logger:
                logger.info('unknown mimetype:{}'.format(mimetype))
            return False
        if mimetype_sets is None and maintype == 'image':
            return True
        if mimetype_sets and \
                any(maintype == x[0] for x in mimetype_sets) and \
                any(subtype.lower() == x[1] for x in mimetype_sets):
            return True
        return False

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
        if logger:
            logger.info('add url:{}'.format(url))
        return upload_resp

    # method

    def load_config(self, config_path):
        try:
            with open(config_path) as f:
                self.config = yaml.safe_load(f)
                ctx.log.info(
                    'mitmimage: load {} block regex.'.format(
                        len(self.config.get('block_regex', []))))
                ctx.log.info(
                    'mitmimage: load {} url filename block regex.'.format(
                        len(self.config.get('block_url_filename_regex', []))))
        except Exception as err:
            ctx.log.error('mitmimage: error loading config, {}'.format(err))

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
                ctx.log.info('mitmimage: client initiated with new access key.')
        if "mitmimage_config" in updates and ctx.options.mitmimage_config:
            self.load_config(ctx.options.mitmimage_config)
            self.get_url_filename.cache_clear()
            self.skip_url.cache_clear()
            self.is_valid_content_type.cache_clear()

    @functools.lru_cache(1024)
    def get_url_filename(self, url, max_len=120):
        url_filename = None
        try:
            url_filename = Path(urlparse(url).path).stem
            for item in self.config.get('block_url_filename_regex', []):
                if re.match(item[0], url_filename.lower()):
                    self.logger.info('regex skip url filename:{},{}'.format(item[1], url))
                    url_filename = None
                if url_filename and len(url_filename) > max_len:
                    self.logger.info(
                        'url filename too long:{}...,{}'.format(
                            url_filename[:max_len], url))
                    url_filename = None
        except Exception:
            pass
        return url_filename

    @functools.lru_cache(1024)
    def skip_url(self, url):
        for item in self.config.get('block_regex', []):
            if re.match(item[0], url):
                return item

    def add_additional_url(self, url):
        additional_url = []
        match = re.match(r'https:\/\/nitter.net\/pic\/media%2F(.*)%3F', url)
        if match and match.groups():
            additional_url.append(
                'https://nitter.net/pic/media%2F{}%3Fname%3Dorig'.format(
                    match.groups()[0])
            )
        match = re.match(r'https:\/\/i.ytimg.com\/vi\/(.*)\/hqdefault.*', url)
        if match and match.groups():
            additional_url.append(
                'https://www.youtube.com/watch?v={}'.format(
                    match.groups()[0])
            )
        if additional_url:
            for new_url in additional_url:
                self.client.add_url(new_url, page_name='mitimimage_plus')
                self.logger.info('additional_url:{}'.format(new_url))

    @concurrent
    def request(self, flow: http.HTTPFlow):
        url = flow.request.pretty_url
        match_regex = self.skip_url(url)
        if match_regex:
            self.logger.info('request regex skip url:{},{}'.format(match_regex[1], url))
            self.remove_from_view(view=self.view, flow=flow)
            return
        mimetype: Optional[str] = None
        valid_content_type = False
        try:
            mimetype = cgi.parse_header(mimetypes.guess_type(url)[0])[0]
            mock_flow = mock.Mock()
            mock_flow.response.data.headers = {'Content-type': mimetype}
            valid_content_type = \
                self.is_valid_content_type(
                    mock_flow, self.logger, self.config.get('mimetype_regex', None))
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
            self.remove_from_view(view=self.view, flow=flow)
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
        self.remove_from_view(view=self.view, flow=flow)

    @concurrent
    def response(self, flow: http.HTTPFlow) -> None:
        """Handle response."""
        url = flow.request.pretty_url
        match_regex = self.skip_url(url)
        if match_regex:
            self.logger.info('response regex skip url:{},{}'.format(match_regex[1], url))
            self.remove_from_view(view=self.view, flow=flow)
            return
        valid_content_type = self.is_valid_content_type(
            flow, logger=self.logger,
            mimetype_sets=self.config.get('mimetype_regex', None))
        if not valid_content_type:
            self.remove_from_view(view=self.view, flow=flow)
            return
        if url not in self.data:
            self.data[url] = {'hydrus': None}
        url_data = self.data[url].get('hydrus', None)
        if not url_data:
            #  huf = hydrus url files
            huf_resp = self.get_url_files(url)
            self.logger.debug('huf response:{},{}'.format(url, huf_resp))
            self.data[url]['hydrus'] = huf_resp
            url_data = huf_resp
        else:
            huf_resp = url_data
        url_file_statuses = huf_resp.get('url_file_statuses', None)
        if (url_file_statuses and
                any(x['status'] == ImportStatus.Exists for x in url_file_statuses)):
            self.logger.debug('url_file_statuses:{},{}'.format(url, url_file_statuses))
        else:
            # upload file
            upload_resp = self.upload(
                flow, self.client, self.logger, url_data.get('normalised_url', None))
            # update data
            if 'url_file_statuses' in self.data[url]['hydrus']:
                self.data[url]['hydrus']['url_file_statuses'].append(upload_resp)
            else:
                self.data[url]['hydrus']['url_file_statuses'] = [upload_resp]
        url_filename = self.get_url_filename(url)
        kwargs = {'page_name': 'mitmimage'}
        if url_filename:
            kwargs['service_names_to_tags'] = {
                'my tags': ['filename:{}'.format(url_filename), ]}
        self.client.add_url(url, **kwargs)
        self.logger.info('add url:{}'.format(url))
        self.add_additional_url(url)
        self.remove_from_view(view=self.view, flow=flow)

    # command

    @command.command('mitmimage.log_hello')
    def log_hello(self):
        ctx.log.info('mitmimage: hello')

    @command.command("mitmimage.clear_data")
    def clear_data(self) -> None:
        self.data = {}
        ctx.log.info('mitmimage: data cleared')

    @command.command('mitmimage.ipdb')
    def ipdb(self, flows: typing.Sequence[Flow] = None) -> None:
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
            url = flow.request.pretty_url
            match_regex = self.skip_url(url)
            if match_regex:
                self.logger.info(
                    'manual upload regex skip url:{},{}'.format(match_regex[1], url))
                self.remove_from_view(self.view, flow)
                continue
            resp = self.upload(flow, self.client, logger)
            resp_history.append(resp)
            if remove and resp is not None:
                self.remove_from_view(self.view, flow)
        logger.info(Counter([
            x['status'] for x in resp_history if x is not None]))


addons = [MitmImage()]
