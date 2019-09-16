import logging.config, socket, sys

from logging import Logger, StreamHandler
from queue import Queue

from utils import Utils, SocketHelper, SocketReadError, SocketWriteError


class Server:

    def __init__(self, addr: tuple):
        self.logger = self.init_logger()
        self.connection_details = addr
        self.socket = self.init_socket(self.connection_details)
        self.message_q = Queue()
        self._stop = False  # state to determine if stopping server requested
        self._socket_helper = SocketHelper()  # helper with common socket operations

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
        try:
            self.logger.debug("Performing read from socket")
            msg = self._socket_helper.read(sock)
            self.logger.debug("Read from socket completed successfully")
            return msg
        except SocketReadError:
            raise SocketReadError

    def write(self, sock: socket, msg: bytes) -> None:
        self.logger.debug("Performing write to socket of size {}".format(len(msg)))
        try:
            self._socket_helper.write(sock, msg)
        except SocketWriteError:
            raise SocketWriteError
        self.logger.debug("Write to socket completed successfully")

    def queue_size(self):
        return self.message_q.qsize()

    def serve_forever(self):
        while not self._stop:
            # connect new client:
            conn, addr = self.socket.accept()
            conn.settimeout(Utils.TIMEOUT)
            self.logger.info("New client {} has arrived".format(conn.getpeername()))
            response = {}
            try:
                # read from socket:
                data = self.read(conn)
                self.logger.info("Read successfully data from client")
                if not data:
                    break  # client disconnected while writing to socket
                # write response to socket:
                response = self.handle_request(Utils.json_decode(data))
                self.write(conn, Utils.json_encode(response))
                self.logger.info("Sent successfully {}".format(response))
            except (socket.timeout, SocketReadError, SocketWriteError) as e:
                self._handle_socket_err(response, e)
            finally:
                # close connection:
                self._close_connection(conn)
                self.logger.info("Closed client connection successfully")
        self.stop_server()

    def handle_request(self, request: dict) -> dict:
        self.logger.debug("Handling request {}".format(request))

        command_type, payload, status_code = request.get("type"), request.get("payload"), Utils.STATUS_OK
        if command_type == "ENQ":
            status_code, payload = self._handle_enq(payload)
        elif command_type == "DEQ":
            status_code, payload = self._handle_deq(payload)
        elif command_type == "DEBUG":
            status_code, payload = self._handle_debug(payload)
        elif command_type == "STAT":
            status_code, payload = self._handle_stat(payload)
        elif command_type == "STOP" or command_type == "EXIT":
            status_code, payload = self._handle_stop(payload)

        self.logger.debug("Finished handling request")
        response = self._create_response(status_code, command_type, payload)
        return response

    def stop_server(self):
        self.logger.info("Stopping server....")
        self.socket.close()

    # ---------------------------------------------------------------------------
    # Helper functions at module level.
    # ---------------------------------------------------------------------------
    def _handle_enq(self, payload: dict) -> tuple:
        self.logger.debug("Handling enqueue request")
        self.message_q.put(payload)
        payload = {}    # response should be empty
        return Utils.STATUS_OK, payload

    def _handle_deq(self, payload: dict) -> tuple:
        self.logger.debug("Handling dequeue request")
        if self.message_q.empty():
            self.logger.debug("Trying to dequeue empty queue")
            self._set_error(payload, "No messages in queue")
            return Utils.STATUS_ERR, payload
        else:
            payload = self.message_q.get()
            self.logger.debug("Queued message from queue successfully")
            return Utils.STATUS_OK, payload

    def _handle_debug(self, payload: dict) -> tuple:
        self.logger.debug("Handling debug request")
        handler = self.logger.handlers[0]
        if type(handler) is not StreamHandler:
            self.logger.error("Logging configuration does not match logic")
            self._set_error(payload, "Logging errors")
            return Utils.STATUS_ERR, payload
        if payload['debug'] == "on":
            handler.setLevel(logging.DEBUG)
            self.logger.info("Changed logging level to DEBUG")
        else:
            handler.setLevel(logging.INFO)
            self.logger.info("Changed logging level to INFO and not DEBUG")
        return Utils.STATUS_OK, payload

    def _handle_stat(self, payload: dict) -> tuple:
        self.logger.debug("Handling stat request")
        self._add_to_payload(payload, "size", self.message_q.qsize())
        return Utils.STATUS_OK, payload

    def _handle_stop(self, payload: dict) -> tuple:
        # Server will stop after return message to client
        self.logger.debug("Handling stop request")
        self._stop = True
        self._add_to_payload(payload, "message", "server stopped")
        return Utils.STATUS_OK, payload

    def _set_error(self, payload: dict, e: str) -> None:
        self._add_to_payload(payload, "message", e)

    def _add_to_payload(self, payload: dict, key: str, val: object) -> None:
        payload[key] = val

    def _create_response(self, status: str, type: str, payload: dict) -> dict:
        response = {
            "status": status,
            "type": type,
            "payload": payload
        }
        return response

    def _handle_socket_err(self, response, e) -> None:
        self.logger.error(e)
        self._set_error(response, e.args[0])

    def _close_connection(self, conn: socket) -> None:
        self.logger.debug("Closing connection to client {}".format(conn.getpeername()))
        conn.close()


if __name__ == '__main__':

    Utils.validate_launch(sys.argv, "server")
    host, port = sys.argv[2].split(":")

    server = Server((host, int(port)))
    server.serve_forever()
