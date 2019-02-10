import unittest

from mitmproxy_image.__main__ import create_app


class Mitmproxy_imageTestCase(unittest.TestCase):

    def setUp(self):
        app = create_app()
        self.app = app.test_client()

    def test_index(self):
        rv = self.app.get('/')
        self.assertIn('Mitmproxy-Image', rv.data.decode())


if __name__ == '__main__':
    unittest.main()
