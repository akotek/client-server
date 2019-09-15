import unittest

from server import Server


class MyTestCase(unittest.TestCase):

    def setUp(self):
        addr = ('127.0.0.1', 301)
        self.server = Server(addr)

    def tearDown(self):
        self.server.stop_server()

    def test_read(self):
        pass

    def test_write(self):
        pass

    def test_handle_command_enqueue(self):
        request = {
            "type": "ENQ",
            "payload": {
                "1": "is bad",
            }
        }
        expected = {
            "status": "OK",
            "type": "ENQ",
            "payload": {}
        }
        self.assertEqual(expected, self.server.handle_request(request))
        self.assertEqual(1, self.server.queue_size())

    def test_handle_command_dequeue_fifo_order(self):
        req1 = {
            "type": "ENQ",
            "payload": {
                "1": "is bad",
            }
        }
        req2 = {
            "type": "ENQ",
            "payload": {
                "2": "is better",
            }
        }
        self.server.handle_request(req1)
        self.server.handle_request(req2)
        expected = {
            "status": "OK",
            "type": "DEQ",
            "payload": req1.get('payload')
        }
        self.assertEqual(expected, self.server.handle_request(self._gen_deq_req()))

    def test_handle_command_dequeue_empty_stack(self):
        expected = {
            "status": "ERR",
            "type": "DEQ",
            "payload": {
                "message": 'No messages in queue'
            }
        }
        self.assertEqual(expected, self.server.handle_request(self._gen_deq_req()))

    def test_handle_stat(self):
        pass

    def test_handle_command_debug(self):
        pass

    def _gen_deq_req(self):
        return {
            "type": "DEQ",
        }

if __name__ == '__main__':
    unittest.main()
