import logging
import os
from argparse import Namespace
from unittest import mock
from urllib.parse import urlparse

import pytest

from mitmproxy_image.script import GhMode, MitmImage, get_mimetype

PICKLE_PATH = os.path.join(os.path.dirname(__file__), "pickle", "20200120_223805.pickle")
pickle_path_exist = pytest.mark.skipif(
    not os.path.isfile(PICKLE_PATH), reason="No pickled data found."
)


def test_mitmimage_init():
    MitmImage()


@pytest.mark.parametrize(
    "mimetype, exp_res, config_mimetype",
    [
        [None, False, None],
        ["jpg", True, None],
        ["image/jpeg", True, None],
        ["image/jpeg", True, []],
    ],
)
def test_is_valid_content_type_mimetype(mimetype, exp_res, config_mimetype):
    obj = MitmImage()
    if config_mimetype is not None:
        obj.config["mimetype"] = config_mimetype
    assert obj.is_valid_content_type(mimetype=mimetype) == exp_res


def get_au_regex_rules_test_data():
    """get addditional url regex rules."""
    obj = MitmImage()
    obj.load_config(config_path=obj.default_config_path)
    res = []
    for rule in filter(lambda x: len(x) > 3, getattr(obj, "config", {}).get("add_url_regex", [])):
        page_name = rule[4] if 4 < len(rule) else "mitmimage_plus"
        for sub_data in rule[3]:
            res.append(sub_data + [page_name])
    return res


@pytest.mark.parametrize("url, exp_url, page_name", get_au_regex_rules_test_data())
def test_add_additional_url(url, exp_url, page_name):
    class MockQueue:
        history = []

        def put_nowait(self, *args):
            self.history.append(args)

    obj = MitmImage()
    obj.load_config(config_path=obj.default_config_path)
    if not obj.add_url_regex:
        logging.info("No add_url_regex")
    obj.client_queue = MockQueue()
    obj.add_additional_url(url)
    history = [
        (x[0][1].get("url", None), x[0][1].get("page_name", None)) for x in obj.client_queue.history
    ]
    assert (exp_url, page_name) in history


@pytest.mark.parametrize(
    "flow, url, exp_res",
    [
        [Namespace(response=None), None, None],
        [None, "http://example.com/index.html", "text/html"],
        [None, "http://example.com/index.random", None],
        [None, "http://google.com", "application/x-msdos-program"],
        [None, "http://google.com/1.jpg", "image/jpeg"],
        [Namespace(response=None), "http://example.com/index.html", None],
    ],
)
def test_get_mimetype(flow, url, exp_res):
    if all([flow, url]):
        with pytest.raises(ValueError):
            get_mimetype(flow, url)
    else:
        assert get_mimetype(flow, url) == exp_res


@pytest.mark.parametrize(
    "mode, url_data, ufss, exp_res",
    (
        [GhMode.ON_EMPTY, {}, [], (set(), {}, {})],
        [GhMode.ON_EMPTY, {}, [{"hash": "hash1"}], ({"hash1"}, {"url": {"hash1"}}, {})],
        [
            GhMode.ON_EMPTY,
            {"url": {"hash2"}},
            [{"hash": "hash1"}],
            ({"hash2"}, {"url": {"hash2"}}, {}),
        ],
        [
            GhMode.ON_EMPTY,
            {},
            [{"hash": "hash1", "status": "s1"}],
            ({"hash1"}, {"url": {"hash1"}}, {"status": "s1"}),
        ],
        [
            GhMode.ALWAYS,
            {},
            [{"hash": "hash1", "status": "s1"}],
            ({"hash1"}, {"url": {"hash1"}}, {"hash1": "s1"}),
        ],
        [
            GhMode.ALWAYS,
            {"url": {"hash2"}},
            [{"hash": "hash1"}],
            ({"hash1", "hash2"}, {"url": {"hash2", "hash1"}}, {}),
        ],
    ),
)
def test_get_hashes(mode, url_data, exp_res, ufss):
    obj = MitmImage()
    obj.client = mock.Mock()
    obj.client.get_url_files.return_value = {"url_file_statuses": ufss}
    obj.url_data.update(url_data)
    res = obj.get_hashes("url", mode)
    assert (res, dict(obj.url_data), obj.hash_data) == exp_res


@pytest.mark.golden_test("data/url*.yaml")
def test_urls(golden):
    obj = MitmImage()
    obj.load_config("/home/r3r/mitmimage.yaml")
    obj.client_queue.put_nowait = mock.Mock()
    flow = mock.Mock()
    flow.request.method = "get"
    res = []
    for url in (urls := sorted(golden["urls"])):
        flow.request.pretty_url = url
        flow.request.pretty_host = urlparse(url).netloc
        obj.client_queue.put_nowait.reset_mock()
        obj.add_additional_url(url)
        call_args_list = obj.client_queue.put_nowait.call_args_list
        if not call_args_list:
            call_args_list = []
        call_args_output = []
        for call_args in call_args_list:
            call_args_output.append(list(call_args)[0][0][1])
        if call_args_output:
            res.append([url, obj.check_request_flow(flow), call_args_output])
        else:
            res.append([url, obj.check_request_flow(flow)])
    assert res == golden.out["output"]
    assert list(urls) == golden.out["urls"]


if __name__ == "__main__":
    pytest.main()
