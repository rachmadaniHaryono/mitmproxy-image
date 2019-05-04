import unittest

from PIL import Image
from sqlalchemy_utils import database_exists
import pytest

from mitmproxy_image.__main__ import (
    create_app,
    process_info,
    DB,
    Sha256Checksum,
    Url,
)


class Mitmproxy_imageTestCase(unittest.TestCase):

    def setUp(self):
        app = create_app('sqlite://', debug=True, testing=True)
        self.app = app.test_client()

    def test_index(self):
        rv = self.app.get('/')
        self.assertIn('Mitmproxy-Image', rv.data.decode())

    def test_url_list(self):
        assert DB.engine.dialect.has_table(DB.engine, 'url')
        rv = self.app.get('/api/url')
        jv = rv.get_json()
        assert not jv
        rv = self.app.post('/api/url', data={'value': 'http://example.com'})
        jv = rv.get_json()
        #  assert jv


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


def test_process_info(tmp_path):
    from PIL import Image
    exp_res = {
        'ext': 'jpeg',
        'filesize': 661,
        'height': 30,
        'img_format': 'JPEG',
        'img_mode': 'RGB',
        'value':
        '71bfa8254d2cbdbdfe56938cdbf0c759be4d3d80818b56652de89fc589a70cbe',
        'width': 60}
    img = Image.new('RGB', (60, 30), color='red')
    test_img = tmp_path / 'test.jpg'
    test_dir = tmp_path / 'test_dir'
    test_dir.mkdir()
    img.save(test_img)
    with open(test_img, 'rb') as f:
        res = process_info(f, folder=test_dir)
    assert exp_res == res
    exp_file = test_dir / '71' / \
        '71bfa8254d2cbdbdfe56938cdbf0c759be4d3d80818b56652de89fc589a70cbe' \
        '.jpeg'
    assert exp_file.is_file()


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


if __name__ == '__main__':
    pytest.main()
