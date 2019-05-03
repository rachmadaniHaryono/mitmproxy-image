import unittest

from sqlalchemy_utils import database_exists
import pytest

from mitmproxy_image.__main__ import create_app, process_info, DB, Url


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
    app = create_app(db_uri='sqlite://', debug=True, testing=True)
    session = DB.session
    with app.app_context():
        m, created = Url.get_or_create('http://example.com', session)
        session.commit()
        assert created
        m_dict = m.to_dict()
        m_dict.pop('last_redirect')
        m_dict.pop('last_check')
        assert m_dict == {
            'check_counter': '0',
            'id': '1',
            'redirect_counter': '0',
            'value': 'http://example.com'
        }


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
