import logging.config
import socket
import sys

# CONSTANTS:
from logging import Logger
from queue import Queue

from utils import Utils, SocketUtils


class Server:

    def __init__(self, addr: tuple):
        self.logger = self.init_logger()
        self.connection_details = addr
        self.socket = self.init_socket(self.connection_details)
        self.current_clients = {}  # maps fd to client peer name
        self.message_q = Queue()

    def init_socket(self, addr: tuple):
        s = socket.socket()
        s.bind(addr)
        s.listen(Utils.MAX_CLIENTS)
        s.settimeout(Utils.TIMEOUT)
        self.logger.info("server initialized and listening on {}".format(self.connection_details))
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
        # add message size as prefix (int 4bytes):
        self.logger.debug("Sending message of size {}".format(len(msg)))
        sock.sendall(SocketUtils.wrap_msg(msg))

    def close_connection(self, conn):
        peername = self.current_clients[conn.fileno()]
        self.logger.debug("Closing connection to client {}".format(peername))
        del self.current_clients[conn.fileno()]
        conn.close()

    def serve_forever(self):
        while True:
            conn, addr = self.socket.accept()
            conn.settimeout(Utils.TIMEOUT)  # set timeout for socket read
            self.current_clients[conn.fileno()] = conn.getpeername()
            response = {}
            try:
                data = self.read(conn)
                if not data:
                    self.close_connection(conn)  # client closed it connection
                else:
                    response = self.handle_request(Utils.json_decode(data))
            except (socket.timeout, SocketReadError) as e:
                self.logger.error(e)
                self._set_error(response, e)
            finally:
                self.write(conn, Utils.json_encode(response))
                self.logger.info("Sent successfully {}".format(response))

    def handle_request(self, request: dict) -> dict:
        self.logger.debug("Handling request {}".format(request))

        command_type, payload = request.get("type"), request.get("payload")
        response = dict(type=command_type, payload={})
        if command_type == "ENQ" and payload:
            self._handle_enq(payload)
        elif command_type == "DEQ":
            self._handle_deq(response)
        elif command_type == "DEBUG" and payload:
            self._handle_debug(payload)
        elif command_type == "STAT":
            self._handle_stat(response)
        elif command_type == "STOP":
            self._handle_stop(response)

        self.logger.debug("Finished handling request")
        return response

    def stop_server(self):
        self.logger.info("Stopping server....")
        pass

    # ---------------------------------------------------------------------------
    # Helper functions at module level.
    # ---------------------------------------------------------------------------
    def _handle_enq(self, payload):
        self.logger.debug("Handling enqueue request")
        self.message_q.put(payload)

    def _handle_deq(self, response: dict):
        self.logger.debug("Handling dequeue request")
        if self.message_q.empty():
            self.logger.debug("No messages to dequeue")
            self._set_error(response, "No messages in queue")
        else:
            response['payload'] = self.message_q.get()

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
        self.logger.debug("Handling stop request")
        self._add_to_payload(response, "message", "server stopped")
        self.stop_server()

    def _set_error(self, response: dict, e: str):
        response["status"] = "ERR"
        self._add_to_payload(response, "message", e)

    def _add_to_payload(self, response: dict, key: str, val: object):
        response.get('payload')[key] = val


class SocketReadError(RuntimeError):
    DEFAULT = "Error reading from socket"

    def __init__(self, message: str = DEFAULT) -> None:
        super().__init__(message)


if __name__ == '__main__':
    Utils.validate_launch(sys.argv, "server")
    host, port = sys.argv[2].split(":")
    server = Server((host, int(port)))
    server.serve_forever()
