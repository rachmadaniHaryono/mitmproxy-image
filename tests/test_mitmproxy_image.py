import logging
import os
import pickle
import unittest
from unittest import mock
from unittest.mock import Mock

import pytest
from PIL import Image
from sqlalchemy_utils import database_exists

from mitmproxy_image.__main__ import (
    DB,
    MitmImage,
    MitmUrl,
    Sha256Checksum,
    Url,
    check_valid_flow_response,
    create_app,
    is_content_type_valid
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
            'value':
                '71bfa82'
                '54d2cbdbdfe56938cdbf0c759be4d3d80818b56652de89fc589a70cbe',
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


def test_init_mitmimage():
    MitmImage()


@pytest.mark.parametrize('content_type, exp_res', [
    [None, False],
    ['image/webp', True],
    ['text/html; charset=utf-8', False],
    ['application/javascript', False],
    ['application/json; charset=utf-8', False],
    ['image/gif;charset=utf-8', False],
])
def test_is_content_type_valid(content_type, exp_res):
    flow = Mock()
    flow.response.headers = {'content-type': content_type}
    assert exp_res == is_content_type_valid(flow)


def test_check_valid_flow_response():
    m_flow = Mock()
    resp_pickle = os.path.join(
        os.path.dirname(__file__), 'pickle', '20200120_223805.pickle')
    with open(resp_pickle, 'rb') as f:
        m_flow.request, m_flow.response = pickle.load(f)
    with mock.patch('mitmproxy_image.__main__.ctx'):
        res = check_valid_flow_response(
            m_flow, logging.getLogger(__name__))
    assert vars(res[0]) == vars(MitmUrl(m_flow))
    assert res[1:] == ('', 'info', True)


def test_mitmurl():
    m_flow = Mock()
    resp_pickle = os.path.join(
        os.path.dirname(__file__), 'pickle', '20200120_223805.pickle')
    with open(resp_pickle, 'rb') as f:
        m_flow.request, m_flow.response = pickle.load(f)
    obj = MitmUrl(m_flow)
    assert vars(obj) == {
        'value': 'https://pocket-syndicated-publisher-logos.s3.amazonaws.com/5d001cdc87f29.png',  # NOQA
        'trash_status': 'unknown', 'zero_filesize': 'unknown',
        'host': 'pocket-syndicated-publisher-logos.s3.amazonaws.com',
        'port': 443, 'content_type': 'image/png', 'check_counter': 0,
        'redirect_counter': 0, 'checksum_value': None,
        'checksum_ext': None}


if __name__ == '__main__':
    pytest.main()
