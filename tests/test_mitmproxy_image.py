import os
import tempfile
import traceback
import unittest
from unittest import mock

import pytest
from click.testing import CliRunner
from mitmproxy.tools import console

from mitmproxy_image.__main__ import cli, create_app
from mitmproxy_image.script import MitmImage

PICKLE_PATH = os.path.join(
    os.path.dirname(__file__), "pickle", "20200120_223805.pickle"
)
pickle_path_exist = pytest.mark.skipif(
    not os.path.isfile(PICKLE_PATH), reason="No pickled data found."
)


class Mitmproxy_imageTestCase(unittest.TestCase):
    def setUp(self):
        app = create_app("sqlite://", debug=True, testing=True)
        self.app = app.test_client()

    def test_index(self):
        rv = self.app.get("/")
        self.assertIn("mitmproxy_image", rv.data.decode())


def test_create_app():
    assert create_app()


def test_mitmimage_init():
    MitmImage()


@pytest.mark.parametrize(
    "headers,res",
    [
        [{}, False],
        [{"Content-type": "text/html"}, False],
        [{"Content-type": "image/webp"}, True],
    ],
)
def test_mitmimage_is_valid_content_type(headers, res):
    mock_flow = mock.Mock()
    mock_flow.response.data.headers = headers
    obj = MitmImage()
    assert obj.is_valid_content_type(mock_flow) == res


def test_is_valid_content_type_url():
    url = "https://net/v/t1.0-9/4_o.jpg?_nc_cat=100"
    obj = MitmImage()
    assert obj.is_valid_content_type(url=url)


@pytest.fixture
def client():
    app = create_app()
    db_fd, app.config["DATABASE"] = tempfile.mkstemp()
    app.config["TESTING"] = True

    with app.test_client() as client:
        yield client

    os.close(db_fd)
    os.unlink(app.config["DATABASE"])


def test_empty_db(client):
    """Start with a blank database."""
    rv = client.get("/")
    vars_rv = vars(rv)
    assert {
        "_on_close": [],
        "_status": "200 OK",
        "_status_code": 200,
        "direct_passthrough": False,
    } == {
        key: val
        for key, val in vars_rv.items()
        if key in ["_on_close", "_status", "_status_code", "direct_passthrough"]
    }

    assert rv.headers["Content-Type"] == "text/html; charset=utf-8"
    assert int(rv.headers["Content-Length"]) > 0


def get_au_regex_rules_test_data():
    """get addditional url regex rules."""
    obj = MitmImage()
    obj.load_config(config_path=obj.default_config_path)
    res = []
    for rule in filter(lambda x: len(x) > 3, obj.config.get("add_url_regex", [])):
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
    obj.client_queue = MockQueue()
    obj.add_additional_url(url)
    history = [
        (x[0][1][0], x[0][2].get("page_name", None)) for x in obj.client_queue.history
    ]
    assert (exp_url, page_name) in history


def test_run_mitmproxy_cmd(monkeypatch):
    # NOTE: listen-host not use 127.0.0.1 so it can be tested
    #  while program with default value can run
    master = mock.Mock()
    monkeypatch.setattr(console.master, "ConsoleMaster", master)
    runner = CliRunner()
    result = runner.invoke(cli, ["run-mitmproxy", "--listen-host", "127.0.0.2"])
    exc = result.exception

    assert result.exit_code == 0, "".join(
        traceback.format_exception(etype=type(exc), value=exc, tb=exc.__traceback__)
    )


if __name__ == "__main__":
    pytest.main()
