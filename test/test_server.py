import unittest

from server import Server


class MyTestCase(unittest.TestCase):

    def setUp(self):
        self.addr = ('127.0.0.1', 301)
        self.server = Server(self.addr)

    def tearDown(self):
        self.server.stop_server()

    def test_read(self):
        # Integration test
        pass

    def test_write(self):
        # Integration test
        pass

    def test_handle_command_enqueue(self):
        request = self._gen_req("ENQ", payload={"1": "is bad"})
        expected = {
            "status": "OK",
            "type": "ENQ",
            "payload": {}
        }
        self.assertEqual(expected, self.server.handle_request(request))
        self.assertEqual(1, self.server.queue_size())

    def test_handle_command_dequeue_fifo_order(self):
        req1 = self._gen_req("ENQ", payload={"1": "is bad"})
        req2 = self._gen_req("ENQ", payload={"2": "is better"})
        self.server.handle_request(req1)
        self.server.handle_request(req2)
        expected = {
            "status": "OK",
            "type": "DEQ",
            "payload": req1.get('payload')
        }
        self.assertEqual(expected, self.server.handle_request(self._gen_req("DEQ")))

    def test_handle_command_dequeue_empty_stack(self):
        expected = {
            "status": "ERR",
            "type": "DEQ",
            "payload": {
                "message": 'No messages in queue'
            }
        }
        self.assertEqual(expected, self.server.handle_request(self._gen_req("DEQ")))

    def test_handle_command_debug(self):
        req1 = self._gen_req("DEBUG", payload={"debug": "on"})
        self.server.handle_request(req1)
        DEBUG, INFO = 10, 20
        self.assertEqual(DEBUG, self.server.logger.level)
        req2 = self._gen_req("DEBUG", payload={"debug": "off"})
        self.server.handle_request(req2)
        self.assertEqual(INFO, self.server.logger.level)

    def test_handle_stat(self):
        req1 = self._gen_req("ENQ", payload={"test": "test"})
        self.server.handle_request(req1)
        req2 = self._gen_req("STAT")
        expected = {
            "status": "OK",
            "type": "STAT",
            "payload": {
                "size": 1
            }
        }
        self.assertEqual(expected, self.server.handle_request(req2))

    def test_handle_stop(self):
        request = self._gen_req("STOP")
        self.server.handle_request(request)
        self.assertEqual(True, self.server._stop)

    def test_handle_exit(self):
        request = self._gen_req("EXIT")
        self.server.handle_request(request)
        self.assertEqual(True, self.server._stop)

    def _gen_req(self, type, payload=None):
        if payload is None:
            payload = {}
        request = {
            "type": type,
            "payload": payload
        }
        return request


if __name__ == '__main__':
    unittest.main()
