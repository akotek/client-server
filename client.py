import json, sys, logging.config, uuid, socket
from logging import Logger
from utils import Utils, SocketHelper, SocketReadError, SocketWriteError


class Client:

    def __init__(self, addr: tuple):
        self.uid = str(uuid.uuid4().int)
        self.connection_details = addr
        self.socket = self.init_socket()
        self.logger = self.init_logger()
        self._socket_helper = SocketHelper()

    def init_socket(self):
        s = socket.socket()
        return s

    def connect(self):
        self.logger.debug("Starting a new socket connection to {}".format(self.connection_details))
        if not self.socket:
            self.socket = self.init_socket()
        self.socket.connect(self.connection_details)
        self.socket.settimeout(Utils.TIMEOUT)  # timeout for socket conn
        self.logger.debug("Client connected successfully")

    def init_logger(self) -> Logger:
        logging.config.fileConfig('logging.conf')
        logger = logging.getLogger('Client')
        return logger

    # ---------------------------------------------------------------------------
    # Client API,
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

    def close_connection(self):
        self.socket.close()
        self.socket = None
        self.logger.info("Closed client socket connection successfully")

    def run(self):

        while True:
            # parse std_input
            in_read = input("Enter wanted command\n").split(" ", 1)
            if not Utils.validate_input(in_read):
                print("Wrong stdin command entered")
                continue

            try:
                # create new connection:
                self.connect()
                self.logger.info("Client connected successfully to {}".format(self.connection_details))
                # send request to server:
                request = self.parse_command(in_read)
                self.write(self.socket, Utils.json_encode(request))
                self.logger.info("Client {} sent successfully command: {}".format(self._get_name(), request))

                # read response from server:
                response = Utils.json_decode(self.read(self.socket))
                self.logger.info("Client {} received successfully response {}".format(self._get_name(), response))
                self.close_connection()
            except (socket.timeout, ConnectionRefusedError, SocketReadError, SocketWriteError) as e:
                self._handle_error(e)
            finally:
                if in_read[0] == "EXIT":
                    self.logger.info("Closing server and existing client stdin")
                    exit()

    # ---------------------------------------------------------------------------
    # Helper functions at module level.
    # ---------------------------------------------------------------------------

    def parse_command(self, s: list) -> dict:
        self.logger.debug("Parsing given string {} to command".format(s))
        type, payload = s[0], {}
        if len(s) == 2:
            if type == "DEBUG":
                payload = dict(debug=s[1])
            elif type == "ENQ":
                payload = json.loads(s[1])
        request = {
            "type": type,
            "payload": payload
        }
        return request

    def _get_name(self) -> str:
        return '(' + str(self.uid[0:2]) + ')'

    def _handle_error(self, e) -> None:
        self.logger.error("Exception occurred".format(e))
        print("Error {}, occurred".format(e))


if __name__ == '__main__':
    Utils.validate_launch(sys.argv, "client")
    host, port = sys.argv[2].split(":")

    client = Client(addr=(host, int(port)))
    client.run()
