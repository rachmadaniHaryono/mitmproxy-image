import itertools
import logging
import os
from argparse import Namespace
from unittest import mock

import pytest
from hydrus import ConnectionError

from mitmproxy_image.script import MitmImage, get_mimetype

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
    "from_hydrus, valid_ct", itertools.product(["always", "on_empty"], [True, False])
)
def test_get_hashes(from_hydrus, valid_ct):
    obj = MitmImage()

    def is_valid_content_type(url):
        return valid_ct

    obj.is_valid_content_type = is_valid_content_type
    obj.client = mock.Mock()
    obj.client.get_url_files.return_value = {}
    try:
        assert not obj.get_hashes("http://example.com", from_hydrus)
    except ConnectionError as err:
        logging.error(str(err), exc_info=True)


if __name__ == "__main__":
    pytest.main()
