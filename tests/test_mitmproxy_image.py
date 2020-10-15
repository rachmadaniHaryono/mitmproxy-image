import os
import tempfile
import unittest
from unittest import mock

import pytest

from mitmproxy_image.__main__ import create_app
from mitmproxy_image.script import MitmImage

PICKLE_PATH = os.path.join(
    os.path.dirname(__file__), 'pickle', '20200120_223805.pickle')
pickle_path_exist = pytest.mark.skipif(
    not os.path.isfile(PICKLE_PATH), reason='No pickled data found.'
)


class Mitmproxy_imageTestCase(unittest.TestCase):

    def setUp(self):
        app = create_app('sqlite://', debug=True, testing=True)
        self.app = app.test_client()

    def test_index(self):
        rv = self.app.get('/')
        self.assertIn('mitmproxy_image', rv.data.decode())


def test_create_app():
    assert create_app()


def test_mitmimage_init():
    MitmImage()


@pytest.mark.parametrize(
    'headers,res', [
        [{}, False],
        [{'Content-type': 'text/html'}, False],
        [{'Content-type': 'image/webp'}, True],
    ]
)
def test_mitmimage_is_valid_content_type(headers, res):
    mock_flow = mock.Mock()
    mock_flow.response.data.headers = headers
    obj = MitmImage()
    assert obj.is_valid_content_type(mock_flow) == res


@pytest.fixture
def client():
    app = create_app()
    db_fd, app.config['DATABASE'] = tempfile.mkstemp()
    app.config['TESTING'] = True

    with app.test_client() as client:
        yield client

    os.close(db_fd)
    os.unlink(app.config['DATABASE'])


def test_empty_db(client):
    """Start with a blank database."""
    rv = client.get('/')
    vars_rv = vars(rv)
    assert {
        '_on_close': [],
        '_status': '200 OK',
        '_status_code': 200,
        'direct_passthrough': False,
    } == {
        key: val for key, val in vars_rv.items()
        if key in ['_on_close', '_status', '_status_code', 'direct_passthrough']}

    assert rv.headers['Content-Type'] == "text/html; charset=utf-8"
    assert int(rv.headers['Content-Length']) > 0


if __name__ == '__main__':
    pytest.main()
