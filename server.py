import logging.config, socket, sys

from logging import Logger
from queue import Queue

from utils import Utils, SocketUtils, SocketReadError


class Server:

    def __init__(self, addr: tuple):
        self.logger = self.init_logger()
        self.connection_details = addr
        self.socket = self.init_socket(self.connection_details)
        self.message_q = Queue()
        self._stop_requested = False  # state to determine if stopping server requested

    def init_socket(self, addr: tuple):
        s = socket.socket()
        s.bind(addr)
        s.listen(Utils.MAX_CLIENTS)
        self.logger.info("server initialized, listening on {}".format(self.connection_details))
        return s

    def init_logger(self) -> Logger:
        logging.config.fileConfig('logging.conf')
        logger = logging.getLogger('Server')
        return logger

    # ---------------------------------------------------------------------------
    # Server API,
    # Includes public/testable methods:
    # ---------------------------------------------------------------------------
    def read(self, sock: socket) -> bytes:
        hdr_len = 4
        self.logger.debug("Reading from socket {} bytes".format(hdr_len))
        raw_msglen = SocketUtils.recvall(sock, hdr_len)
        if not raw_msglen:
            raise SocketReadError
        msglen = SocketUtils.unwrap_msg(raw_msglen)
        self.logger.debug("Reading from socket {} bytes".format(msglen))
        msg_bytes = SocketUtils.recvall(sock, msglen)
        if not msg_bytes:
            raise SocketReadError
        return msg_bytes

    def write(self, sock: socket, msg: bytes) -> None:
        self.logger.debug("Sending message of size {}".format(len(msg)))
        sock.sendall(SocketUtils.wrap_msg(msg))

    def close_connection(self, conn: socket) -> None:
        self.logger.debug("Closing connection to client {}".format(conn.getpeername()))
        conn.close()

    def serve_forever(self):
        while True:
            conn, addr = self.socket.accept()
            self.logger.info("New client {} has arrived".format(conn.getpeername()))
            response = {}
            try:
                conn.settimeout(Utils.TIMEOUT)
                data = self.read(conn)
                self.logger.info("Read successfully data from client")
                if not data:
                    self.close_connection(conn)
                    self.logger.info("Closed client connection successfully")
                else:
                    response = self.handle_request(Utils.json_decode(data))
            except (socket.timeout, SocketReadError) as e:
                self.logger.error(e)
                self._set_error(response, e.args[0])
            finally:
                self.write(conn, Utils.json_encode(response))
                self.logger.info("Sent successfully {}".format(response))
                self.close_connection(conn)
                if self._stop_requested:
                    self.stop_server()
                    break

    def handle_error(self, response, e):
        self.logger.error(e)
        self._set_error(response, e.args[0])

    def handle_request(self, request: dict) -> dict:
        self.logger.debug("Handling request {}".format(request))

        command_type, payload = request.get("type"), request.get("payload")
        response = dict(status="OK", type=command_type, payload={})
        if command_type == "ENQ" and payload:
            self._handle_enq(payload)
        elif command_type == "DEQ":
            self._handle_deq(response)
        elif command_type == "DEBUG" and payload:
            self._handle_debug(payload)
        elif command_type == "STAT":
            self._handle_stat(response)
        elif command_type == "STOP" or command_type == "EXIT":
            self._handle_stop(response)

        self.logger.debug("Finished handling request")
        return response

    def stop_server(self):
        self.logger.info("Stopping server....")
        self.socket.close()

    # ---------------------------------------------------------------------------
    # Helper functions at module level.
    # ---------------------------------------------------------------------------
    def _handle_enq(self, payload):
        self.logger.debug("Handling enqueue request")
        self.message_q.put(payload)

    def _handle_deq(self, response: dict):
        self.logger.debug("Handling dequeue request")
        if self.message_q.empty():
            self.logger.debug("Trying to dequeue empty queue")
            self._set_error(response, "No messages in queue")
        else:
            response['payload'] = self.message_q.get()
            self.logger.debug("Queued message from queue successfully")

    def _handle_debug(self, payload: dict):
        self.logger.debug("Handling debug request")
        if payload['debug'] == "on":
            self.logger.setLevel(logging.DEBUG)
            self.logger.info("Changed logging level to DEBUG")
        else:
            self.logger.setLevel(logging.INFO)
            self.logger.info("Changed logging level to INFO and not DEBUG")

    def _handle_stat(self, response: dict):
        self.logger.debug("Handling stat request")
        self._add_to_payload(response, "size", self.message_q.qsize())

    def _handle_stop(self, response: dict):
        # Server will stop after return message to client
        self.logger.debug("Handling stop request")
        self._stop_requested = True
        self._add_to_payload(response, "message", "server stopped")

    def _set_error(self, response: dict, e: str):
        response["status"] = "ERR"
        self._add_to_payload(response, "message", e)

    def _add_to_payload(self, response: dict, key: str, val: object):
        payload = response.get('payload')
        if not payload:
            response['payload'] = dict(key=val)
        else:
            payload[key] = val


if __name__ == '__main__':
    Utils.validate_launch(sys.argv, "server")
    host, port = sys.argv[2].split(":")
    server = Server((host, int(port)))
    server.serve_forever()
