import json, unittest
from unittest import mock
from client import Client


class MyTestCase(unittest.TestCase):

    def setUp(self):
        pass
        # self.HOST, self.PORT = '127.0.0.1', 300
        # self.client = Client()
        # self.client.connect(self.HOST, self.PORT)

    def tearDown(self):
        pass
        # self.client.close()

    def test_write_prefixed_bytes(self):
        pass

    def test_read_prefixed_bytes(self):
        pass

    def test_parse_command(self):
        s1 = [
            ['ENQ', u'{"message": "hello"}'], ['ENQ', u'{"status": "ok", "type": "STAT"}']]
        for i in range(len(s1)):
            expected = {
                "type": s1[i][0],
                "payload": json.loads(s1[i][1])
            }
            self.assertEqual(expected, Client.parse_command(s1[i]))

        s2 = ['DEQ', 'STAT', 'STOP', 'EXIT']
        for i in range(len(s2)):
            expected = {
                "type": s2[i],
                "payload": None
            }
            self.assertEqual(expected, Client.parse_command([s2[i]]))

        s3 = [
            ["DEBUG", "on"], ["DEBUG", "off"]
        ]
        for i in range(len(s3)):
            expected = {
                "type": "DEBUG",
                "payload": dict(debug=s3[i][1])
            }
            self.assertEqual(expected, Client.parse_command(s3[i]))

if __name__ == '__main__':
    unittest.main()
