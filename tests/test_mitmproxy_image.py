import logging
import os
import pickle
import threading
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
    is_content_type_valid,
    redirect_flow_request,
    save_flow_response,
    save_to_temp_folder
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
        'checksum_ext': None,
        'pretty_url': 'https://pocket-syndicated-publisher-logos.s3.amazonaws.com/5d001cdc87f29.png'  # NOQA
    }


def test_save_to_temp_folder(tmp_path):
    img = Image.new('RGB', (60, 30), color='red')
    test_img_path = tmp_path / 'test.jpg'
    img.save(test_img_path)
    test_dir = tmp_path / 'test_dir'
    test_dir.mkdir()
    m_sc = Mock()
    hash_ = '71bfa8254d2cbdbdfe56938cdbf0c759be4d3d80818b56652de89fc589a70cbe'
    ext = 'jpeg'
    m_sc.value, m_sc.ext = hash_, ext
    urls = ['http://example.com/1.jpg', 'http://example.com/2.jpg']
    m_sc.urls = []
    for url in urls:
        m_url = Mock()
        m_url.value = url
        m_sc.urls.append(m_url)
    m_file = Mock()
    m_file.name = test_img_path
    save_to_temp_folder(m_sc, m_file, test_dir)
    exp_txt_file = test_dir / (hash_ + '.' + ext + '.txt')
    exp_img_file = test_dir / (hash_ + '.' + ext)
    assert exp_img_file.is_file()
    assert exp_img_file.stat().st_size > 0
    assert exp_txt_file.is_file()
    assert exp_txt_file.stat().st_size > 0
    with open(exp_txt_file) as f:
        assert f.read() == '\n'.join(urls)


def test_save_flow_response(tmp_path):
    m_flow = Mock()
    resp_pickle = os.path.join(
        os.path.dirname(__file__), 'pickle', '20200120_223805.pickle')
    with open(resp_pickle, 'rb') as f:
        m_flow.request, m_flow.response = pickle.load(f)
    m_url = MitmUrl(m_flow)
    app = create_app('sqlite://')
    url_dict = {}
    image_dir = tmp_path / 'image'
    with app.app_context():
        save_flow_response(
            m_url,
            DB.session,
            url_dict,
            threading.Lock(),
            m_flow,
            logging.getLogger(),
            image_dir
        )
    assert url_dict == {m_url.value: m_url}
    assert (
        image_dir /
        '2f' /
        '2fc4424b398e6267cd738c1a67414c2fda6f8a828d45a2cfd072ba057b01d7a7.png'
    ).is_file()
    sc_m = Sha256Checksum.query.filter_by(
        value=m_url.checksum_value).first()
    assert [x.value for x in sc_m.urls] == [m_url.value]


def test_redirect_flow_request(tmp_path):
    m_flow = Mock()
    resp_pickle = os.path.join(
        os.path.dirname(__file__), 'pickle', '20200120_223805.pickle')
    with open(resp_pickle, 'rb') as f:
        m_flow.request, m_flow.response = pickle.load(f)
    m_url = MitmUrl(m_flow)
    app = create_app('sqlite://')
    url_dict = {}
    image_dir = tmp_path / 'image'
    session = DB.session
    logger = logging.getLogger()
    with app.app_context():
        save_flow_response(
            m_url,
            session,
            url_dict,
            threading.Lock(),
            m_flow,
            logger,
            image_dir
        )
    redirect_url = m_url.get_redirect_url('127.0.0.1', '5012')
    redirect_flow_request(
        m_url, m_flow, app, session, url_dict, redirect_url, logger)
    assert m_url.trash_status == 'false'
    assert m_url.redirect_counter == 1
    assert m_flow.request.url == redirect_url


if __name__ == '__main__':
    pytest.main()
