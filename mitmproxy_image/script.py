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
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from unittest import mock
from urllib.parse import unquote_plus, urlparse

import yaml
from hydrus import Client
from mitmproxy import command, ctx, http
from mitmproxy.flow import Flow
from mitmproxy.script import concurrent


class MitmImage:

    url_data: Dict[str, List[str]]
    normalised_url_data: Dict[str, str]
    hash_data: Dict[str, str]
    config: Dict[str, Any]

    def __init__(self):
        self.url_data = {}
        self.normalised_url_data = {}
        self.hash_data = {}
        self.config = {}
        # logger
        logger = logging.getLogger('mitmimage')
        logger.setLevel(logging.INFO)
        # create file handler
        fh = logging.FileHandler(os.path.expanduser('~/mitmimage.log'))
        fh.setLevel(logging.INFO)
        fh.setFormatter(logging.Formatter('%(levelname).1s:%(message)s'))
        logger.addHandler(fh)
        self.logger = logger
        #  other
        self.default_access_key = \
            '918efdc1d28ae710b46fc814ee818100a102786140ede877db94cedf3d733cc1'
        self.default_config_path = os.path.expanduser('~/mitmimage.yaml')
        self.client = Client(self.default_access_key)
        try:
            self.view = ctx.master.addons.get('view')
        except Exception:
            self.view = None

    def is_valid_content_type(self, flow: http.HTTPFlow) -> bool:
        if flow.response is None or (
                hasattr(flow.response, 'data') and
                'Content-type' not in flow.response.data.headers):
            return False
        content_type = flow.response.data.headers['Content-type']
        mimetype = cgi.parse_header(content_type)[0]
        try:
            maintype, subtype = mimetype.lower().split('/')
            subtype = subtype.lower()
        except ValueError:
            self.logger.info('unknown mimetype:{}'.format(mimetype))
            return False
        mimetype_sets = self.config.get('mimetype', [])
        if not mimetype_sets and maintype == 'image':
            return True
        if mimetype_sets and \
                any(maintype == x[0] for x in mimetype_sets) and \
                any(subtype.lower() == x[1] for x in mimetype_sets):
            return True
        return False

    # method

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
                view.sig_view_remove.send(view, flow=f, index=idx)
            del view._store[f.id]
            view.sig_store_remove.send(view, flow=f)

    def upload(self, flow: Union[http.HTTPFlow, Flow]) -> Optional[Dict[str, str]]:
        url = flow.request.pretty_url  # type: ignore
        response = flow.response  # type: ignore
        if response is None:
            self.logger.debug('no response url:{}'.format(url))
            return None
        content = response.get_content()
        if content is None:
            self.logger.debug('no content url:{}'.format(url))
            return None
        # upload file
        upload_resp = self.client.add_file(io.BytesIO(content))
        self.logger.info('uploaded:{},{}'.format(
            upload_resp['status'], url))
        normalised_url = self.get_normalised_url(url)
        self.client.associate_url([upload_resp['hash'], ], [normalised_url])
        # update data
        self.url_data[normalised_url] = upload_resp['hash']
        self.hash_data[upload_resp['hash']] = upload_resp['status']
        return upload_resp

    def load_config(self, config_path):
        try:
            with open(config_path) as f:
                self.config = yaml.safe_load(f)
                view_filter = self.config.get('view_filter', None)
                if view_filter:
                    ctx.options.view_filter = view_filter
                    ctx.log.info("view_filter: {}".format(view_filter))
                ctx.log.info(
                    'mitmimage: load {} block regex.'.format(
                        len(self.config.get('block_regex', []))))
                ctx.log.info(
                    'mitmimage: load {} url filename block regex.'.format(
                        len(self.config.get('block_url_filename_regex', []))))
        except Exception as err:
            if hasattr(ctx, 'log'):
                ctx.log.error('mitmimage: error loading config, {}'.format(err))

    @functools.lru_cache(1024)
    def get_url_files(self, url: str):
        return self.client.get_url_files(url)

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
                ctx.log.info('mitmimage: client initiated with new access key.')
        if "mitmimage_config" in updates and ctx.options.mitmimage_config:
            self.load_config(ctx.options.mitmimage_config)
            self.get_url_filename.cache_clear()
            self.skip_url.cache_clear()

    @functools.lru_cache(1024)
    def get_url_filename(self, url, max_len=120):
        url_filename = None
        try:
            url_filename = unquote_plus(Path(urlparse(url).path).stem)
            for item in self.config.get('block_url_filename_regex', []):
                if re.match(item[0], url_filename.lower()):
                    self.logger.info('rskip filename:{},{}'.format(item[1], url))
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
                try:
                    item[2]
                except IndexError:
                    item.append(False)
                return item

    def add_additional_url(self, url):
        additional_url = []
        regex_sets = self.config.get('add_url_regex', [])
        for regex_set in regex_sets:
            regex, url_fmt = regex_set[:2]
            try:
                log_flag = regex_set[2]
            except IndexError:
                log_flag = False
            match = re.match(regex, url)
            if match and match.groups():
                new_url = url_fmt.format(*match.groups())
                additional_url.append(new_url)
                log_msg = 'original:{}\ntarget:{}'.format(url, new_url)
                log_func = self.logger.info if log_flag else self.logger.debug
                log_func(log_msg)
        if additional_url:
            for new_url in additional_url:
                self.client.add_url(new_url, page_name='mitmimage_plus')
                self.logger.info('+url:{}'.format(new_url))

    def get_normalised_url(self, url: str) -> str:
        if url in self.normalised_url_data:
            return self.normalised_url_data[url]
        normalised_url = self.client.get_url_info(url)['normalised_url']
        self.normalised_url_data[url] = normalised_url
        return normalised_url

    @concurrent
    def request(self, flow: http.HTTPFlow):
        try:
            url = flow.request.pretty_url
            self.add_additional_url(url)
            match_regex = self.skip_url(url)
            if match_regex:
                msg = 'req:rskip url:{},{}'.format(match_regex[1], url)
                self.logger.debug(msg)
                self.remove_from_view(flow=flow)
                return
            mimetype: Optional[str] = None
            valid_content_type = False
            try:
                guessed_type = mimetypes.guess_type(url)
                if guessed_type[0] is not None:
                    mimetype = cgi.parse_header(guessed_type[0])[0]
                    mock_flow = mock.Mock()
                    mock_flow.response.data.headers = {'Content-type': mimetype}
                    valid_content_type = \
                        self.is_valid_content_type(mock_flow)
            except Exception:
                pass
            normalised_url = self.get_normalised_url(url)
            hashes = list(set(self.url_data.get(normalised_url, [])))
            if not hashes:
                if not valid_content_type:
                    self.logger.debug(
                        'invalid guessed mimetype:{},{}'.format(mimetype, url))
                    return
                huf_resp = self.get_url_files(url)
                self.normalised_url_data[url] = huf_resp['normalised_url']
                normalised_url = huf_resp['normalised_url']
                # ufs = get_url_status
                for ufs in huf_resp['url_file_statuses']:
                    ufs_hash = ufs['hash']
                    if normalised_url not in self.url_data:
                        self.url_data[normalised_url] = [ufs_hash]
                    else:
                        self.url_data[normalised_url].append(ufs_hash)
                        self.url_data[normalised_url] = \
                            list(set(self.url_data[normalised_url]))
                    hashes.append(ufs_hash)
            if len(hashes) > 1:
                self.logger.debug('url have multiple hashes:\n{}'.format(url))
                return
            if len(hashes) == 1:
                hash_ = hashes[0]
                if not self.hash_data.get(hash_, None):
                    return
                try:
                    file_data = self.client.get_file(hash_=hash_)
                    flow.response = http.HTTPResponse.make(
                        content=file_data.content,
                        headers={'Content-Type': file_data.headers['Content-Type']})
                    self.logger.info('cached:{},{}'.format(hash_[:7], url))
                    if normalised_url != url:
                        self.logger.debug(
                            'cached:{},{}'.format(hash_[:7], normalised_url))
                    self.remove_from_view(flow=flow)
                except Exception as err:
                    self.logger.error("error:{}\nurl:{}\ndata:{},{}".format(
                        err, url, hash_, self.hash_data.get(hash_, None)))
        except Exception:
            self.logger.exception('request error')

    def responseheaders(self, flow: http.HTTPFlow):
        try:
            url = flow.request.pretty_url
            match_regex = self.skip_url(url)
            if match_regex:
                msg = 'resph:rskip url:{},{}'.format(match_regex[1], url)
                self.logger.debug(msg)
                self.remove_from_view(flow)
                return
            valid_content_type = self.is_valid_content_type(flow)
            if not valid_content_type:
                self.remove_from_view(flow)
        except Exception:
            self.logger.exception('responseheaders error')

    @concurrent
    def response(self, flow: http.HTTPFlow) -> None:
        """Handle response."""
        try:
            url = flow.request.pretty_url
            match_regex = self.skip_url(url)
            if match_regex:
                msg = 'resp:rskip url:{},{}'.format(match_regex[1], url)
                self.logger.debug(msg)
                self.remove_from_view(flow)
                return
            valid_content_type = self.is_valid_content_type(flow)
            if not valid_content_type:
                self.remove_from_view(flow)
                return
            normalised_url = self.get_normalised_url(url)
            hashes = list(set(self.url_data.get(normalised_url, [])))
            upload_resp = None
            if not hashes:
                upload_resp = self.upload(flow)
            url_filename = self.get_url_filename(url)
            kwargs: Dict[str, Any] = {'page_name': 'mitmimage'}
            if url_filename:
                kwargs['service_names_to_additional_tags'] = {
                    'my tags': ['filename:{}'.format(url_filename), ]}
            self.client.add_url(normalised_url, **kwargs)
            log_msg = self.logger.info if not upload_resp else self.logger.debug
            log_msg('add url:{}'.format(url))
            if normalised_url != url:
                self.logger.debug('add url(normalised):{}'.format(normalised_url))
            self.remove_from_view(flow)
        except Exception:
            self.logger.exception('response error')

    # command

    @command.command('mitmimage.log_hello')
    def log_hello(self):  # pragma: no cover
        ctx.log.info('mitmimage: hello')

    @command.command("mitmimage.clear_data")
    def clear_data(self) -> None:
        self.url_data = {}
        self.normalised_url_data = {}
        self.hash_data = {}
        ctx.log.info('mitmimage: data cleared')

    @command.command('mitmimage.ipdb')
    def ipdb(self, flows: typing.Sequence[Flow] = None) -> None:  # pragma: no cover
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

    @command.command('mitmimage.toggle_debug')
    def toggle_debug(self):
        if self.logger.level == logging.DEBUG:
            self.logger.setLevel(logging.INFO)
            self.logger.handlers[0].setLevel(logging.INFO)
        else:
            self.logger.setLevel(logging.DEBUG)
            self.logger.handlers[0].setLevel(logging.DEBUG)
        ctx.log.info('log level:{}'.format(self.logger.level))

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
            url = flow.request.pretty_url  # type: ignore
            self.add_additional_url(url)
            match_regex = self.skip_url(url)
            if match_regex:
                msg = 'upl:rskip url:{},{}'.format(match_regex[1], url)
                self.logger.debug(msg)
                self.remove_from_view(flow)
                continue
            resp = self.upload(flow)
            self.client.add_url(url, page_name='mitmimage')
            resp_history.append(resp)
            if remove and resp is not None:
                self.remove_from_view(flow)
        data = [x['status'] for x in resp_history if x is not None]
        if data:
            logger.info(Counter(data))
        else:
            logger.info('upload finished')


addons = [MitmImage()]
