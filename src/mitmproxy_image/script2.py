#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
resources:

- async https://docs.mitmproxy.org/stable/addons-examples/#nonblocking
- basic https://docs.mitmproxy.org/stable/addons-overview/#anatomy-of-an-addon
- queue https://github.com/mitmproxy/mitmproxy/blob/af5be0b92817eebb534e05fa0cc45127a70fa113/examples/contrib/jsondump.py
"""
import io
import logging
import traceback
from queue import Queue
from threading import Thread

import hydrus_api
from mitmproxy import ctx, flowfilter


class MitmImage:
    def __init__(self):
        self.client_queue = Queue()
        access_key = "4bd08d98f1e566a5ec78afe42c070d303b5340fd47a814782f30b43316c2cecf"
        self.client = hydrus_api.Client(access_key)
        self.num = 0
        self.base_filter = f"~m GET & !(~websocket | ~d '{{}}')".format(
            self.client.api_url
        )
        logging.basicConfig(filename="/tmp/mitmproxy.log")
        self.url_hash_dict = {}
        self.hash_status_dict = {}

    def client_worker(self):
        while True:
            item = self.client_queue.get()
            action = item.get("action")
            try:
                if action == "upload":
                    upload_resp = self.client.add_file(item["content"])
                    url = item["url"]
                    hash_ = upload_resp["hash"]
                    status = upload_resp["status"]
                    self.hash_status_dict[hash_] = status
                    note = upload_resp.pop("note", None)
                    info_data = [f"upload: {url}", str(upload_resp)]
                    if note:
                        info_data.append(f"note: {note}")
                    ctx.log.info("\n".join(info_data))
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
                elif action in ("associate_url", "add_url"):
                    self.client.add_url
                    resp = getattr(self.client, action)(
                        **{k: v for k, v in item.items() if k != "action"}
                    )
                    if resp:
                        ctx.log.info(f"{action}: {resp}")
                else:
                    raise ValueError(f"Unknown action: {action}")
            except Exception as err:
                ctx.log.error(f"client: {err}\n{traceback.format_exc()}")
            self.client_queue.task_done()

    def configure(self, _):
        t = Thread(target=self.client_worker)
        t.daemon = True
        t.start()

    async def request(self, flow):
        pass

    async def response(self, flow):
        if not flowfilter.match(self.base_filter + ' & ~ts "(image|video)"', flow):
            return
        self.client_queue.put(
            {
                "content": io.BytesIO(flow.response.get_content()),
                "url": flow.request.pretty_url,
                "action": "upload",
            }
        )

    def done(self):
        self.client_queue.join()
        self.log_queue.join()


addons = [MitmImage()]
