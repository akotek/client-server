import json, sys, logging.config, uuid, socket
from logging import Logger
from utils import Utils, SocketHelper, SocketReadError, SocketWriteError


class Client:

    def __init__(self, addr: tuple):
        self.uid = str(uuid.uuid4().int)
        self.connection_details = addr
        self.socket = None
        self.logger = self.init_logger()
        self._socket_helper = SocketHelper()

    def connect(self):
        self.socket = socket.socket()  # each connect opens a new socket
        self.socket.connect(self.connection_details)
        self.socket.settimeout(Utils.TIMEOUT)  # timeout for socket conn
        self.logger.info("Client connected successfully to {}".format(self.connection_details))

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
        self.logger.info("Closed client socket connection successfully")

    def run(self):
        while True:
            # parse std_input
            in_read = input("Enter wanted command\n").split(" ", 1)
            if not Utils.validate_input(in_read):
                print("Wrong stdin command entered")
                continue

            self.connect()

            try:
                # send request to server:
                request = self.parse_command(in_read)
                self.write(self.socket, Utils.json_encode(request))
                self.logger.info("Client {} sent successfully command: {}".format(self._get_name(), request))

                # read response from server:
                response = Utils.json_decode(self.read(self.socket))
                self.logger.info("Client {} received successfully response {}".format(self._get_name(), response))
                self.close_connection()
            except (socket.timeout, SocketReadError, SocketWriteError) as e:
                self.logger.error("Exception occurred".format(e))
            else:
                if request.get("type") == "EXIT" or "STOP":
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


if __name__ == '__main__':

    Utils.validate_launch(sys.argv, "client")
    host, port = sys.argv[2].split(":")

    client = Client(addr=(host, int(port)))
    client.run()
