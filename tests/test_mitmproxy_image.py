import unittest

import mitmproxy_image


class Mitmproxy_imageTestCase(unittest.TestCase):

    def setUp(self):
        self.app = mitmproxy_image.app.test_client()

    def test_index(self):
        rv = self.app.get('/')
        self.assertIn('Welcome to mitmproxy_image', rv.data.decode())


if __name__ == '__main__':
    unittest.main()
