import os
import unittest
from unittest import mock

import pytest
from PIL import Image
from sqlalchemy_utils import database_exists

from mitmproxy_image.__main__ import DB, Sha256Checksum, Url, create_app
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
        self.assertIn('Mitmproxy-Image', rv.data.decode())

    def test_url_list(self):
        url_value = 'http://example.com'
        assert DB.engine.dialect.has_table(DB.engine, 'url')
        rv = self.app.get('/api/url')
        jv = rv.get_json()
        assert not jv
        #  rv = self.app.get('/api/url', data={'value': url_value})
        #  assert rv.status_code == 404
        rv = self.app.post('/api/url', data={'value': url_value})
        jv = rv.get_json()
        jv.pop('last_check')
        jv.pop('last_redirect')
        assert jv == {
            'check_counter': 0,
            'id': '1',
            'redirect_counter': 0,
            'value': 'http://example.com'}


def test_get_or_create_url_model():
    db_uri = 'sqlite://'
    app = create_app(db_uri=db_uri, debug=True, testing=True)
    url_value = 'http://example.com/1.html'
    session = DB.session
    with app.app_context():
        m, created = Url.get_or_create(url_value, session)
        session.commit()
        assert created
        m_dict = m.to_dict()
        m_dict.pop('last_redirect')
        m_dict.pop('last_check')
        m_dict.pop('id')
        assert m_dict == {
            'check_counter': '0',
            'redirect_counter': '0',
            'value': url_value
        }


def test_get_or_create_sha256checksum_model(tmp_path):
    app = create_app(db_uri='sqlite://', debug=True, testing=True)
    url = 'http://example.com/1.jpeg'
    session = DB.session
    img = Image.new('RGB', (60, 30), color='red')
    test_img = tmp_path / 'test.jpg'
    test_dir = tmp_path / 'test_dir'
    test_dir.mkdir()
    img.save(test_img)
    hash_ = '71bfa8254d2cbdbdfe56938cdbf0c759be4d3d80818b56652de89fc589a70cbe'
    with app.app_context():
        m, created = Sha256Checksum.get_or_create(
            test_img.as_posix(), url, session, tmp_path.as_posix())
        session.commit()
        assert created
        m_dict = m.to_dict()
        m_dict['urls'][0].pop('last_check')
        m_dict['urls'][0].pop('last_redirect')
        m_dict['urls'][0].pop('redirect_counter')
        assert m_dict == {
            'ext': 'jpeg',
            'filesize': 661,
            'height': 30,
            'img_format': 'JPEG',
            'img_mode': 'RGB',
            'trash': False,
            'urls': [{
                'check_counter': '0',
                'id': '1',
                'value': 'http://example.com/1.jpeg'}],
            'value': hash_,
            'width': 60}


@pytest.mark.parametrize('use_file', [True, False])
def test_create_app(tmp_path, use_file):
    if not use_file:
        assert create_app('sqlite://')
    else:
        test_file = tmp_path / 'test.db'
        db_uri = 'sqlite:///{}'.format(test_file.as_posix())
        #  before create app
        assert not test_file.is_file()
        assert not database_exists(db_uri)
        # create app
        assert create_app(db_uri)
        # after create app
        assert test_file.is_file()
        assert database_exists(db_uri)


def test_mitmimage_init():
    MitmImage()


@pytest.mark.parametrize(
    'valid_ct,data,url,url_files', [
        [False, {}, None, {}],
        [
            True,
            {'http://example.com/1.jpg': {'hydrus': {}}},
            'http://example.com/1.jpg',
            {}
        ],
    ]
)
def test_mitmimage_response(valid_ct, data, url, url_files):
    upload_resp = {'hash': '123', 'status': 1}
    inst = MitmImage()
    mock_flow = mock.Mock()
    mock_flow.request.pretty_url = url
    mock_flow.response.get_content.return_value = b''
    inst.is_valid_content_type = mock.Mock()
    inst.is_valid_content_type.return_value = valid_ct
    mock_client = mock.Mock()
    mock_client.get_url_files.return_value = url_files
    mock_client.add_file.return_value = upload_resp
    inst.client = mock_client
    inst.response(mock_flow)
    assert inst.data == data


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
    assert MitmImage.is_valid_content_type(mock_flow) == res


if __name__ == '__main__':
    pytest.main()
