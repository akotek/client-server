import json, unittest
from unittest import mock
from client import Client
from server import Server


class MyTestCase(unittest.TestCase):

    def setUp(self):
        # set up client object without connection to socket
        addr = ('127.0.0.1', 300)
        self.client = Client(addr)

    def tearDown(self):
        self.client.close_connection()

    def test_parse_command(self):
        s1 = [
            ['ENQ', u'{"message": "hello"}'], ['ENQ', u'{"status": "ok", "type": "STAT"}']]
        for i in range(len(s1)):
            expected = {
                "type": s1[i][0],
                "payload": json.loads(s1[i][1])
            }
            self.assertEqual(expected, self.client.parse_command(s1[i]))

        s2 = ['DEQ', 'STAT', 'STOP', 'EXIT']
        for i in range(len(s2)):
            expected = {
                "type": s2[i],
                "payload": None
            }
            self.assertEqual(expected, self.client.parse_command([s2[i]]))

        s3 = [
            ["DEBUG", "on"], ["DEBUG", "off"]
        ]
        for i in range(len(s3)):
            expected = {
                "type": "DEBUG",
                "payload": dict(debug=s3[i][1])
            }
            self.assertEqual(expected, self.client.parse_command(s3[i]))


if __name__ == '__main__':
    unittest.main()
