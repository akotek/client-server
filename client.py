import json, sys, logging.config, uuid
from socket import socket
from logging import Logger

from utils import Utils, SocketUtils, SocketReadError


class Client:

    def __init__(self, addr: tuple):
        self.connection_details = addr
        self.logger = self.init_logger()
        self.socket = None
        self.uid = str(uuid.uuid4().int)

    def connect(self):
        self.socket = socket()  # each connect opens a new socket
        self.socket.connect(self.connection_details)
        self.socket.settimeout(Utils.TIMEOUT)   # timeout for socket conn
        self.logger.info("Client connected successfully to {}".format(self.connection_details))

    def init_logger(self) -> Logger:
        logging.config.fileConfig('logging.conf')
        logger = logging.getLogger('Client')
        return logger

    # ---------------------------------------------------------------------------
    # Client API,
    # Includes public/testable methods:
    # ---------------------------------------------------------------------------

    @staticmethod
    def parse_command(s: list) -> dict:
        logging.getLogger('Client').debug("Parsing given string {} to command".format(s))
        type, payload = s[0], None
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

    def close_connection(self):
        self.socket.close()
        self.logger.info("Closed client socket connection successfully")

    def run(self):
        while True:

            in_read = input("Enter wanted command\n").split(" ", 1)
            if not Utils.validate_input(in_read):
                print("Wrong stdin command entered")
                continue

            self.connect()

            # WRITE PARSED COMMAND
            request = self.parse_command(in_read)
            self.write(self.socket, Utils.json_encode(request))
            self.logger.info("Client {} sent successfully command: {}".format(self._get_name(), request))

            # READ RESPONSE
            response = Utils.json_decode(self.read(self.socket))
            self.logger.info("Client {} received successfully response {}\n".format(self._get_name(), response))
            self.close_connection()

            if request.get("type") == "EXIT":
                self.logger.info("Closing server and existing client stdin")
                exit()

    # ---------------------------------------------------------------------------
    # Helper functions at module level.
    # ---------------------------------------------------------------------------
    def _get_name(self):
        return '(' + str(self.uid[0:2]) + ')'


if __name__ == '__main__':

    Utils.validate_launch(sys.argv, "client")
    host, port = sys.argv[2].split(":")

    client = Client(addr=(host, int(port)))
    client.run()
