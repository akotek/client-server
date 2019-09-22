import json, re, socket, struct
import logging
from enum import Enum


# ---------------------------------------------------------------------------
# Class for common operations on socket object,
# used by both Server and Client
# ---------------------------------------------------------------------------
class SocketHelper:

    def __init__(self) -> None:
        self.logger = logging.getLogger("Socket")

    def wrap_msg(self, msg: bytes) -> bytes:
        return struct.pack('>I', len(msg)) + msg

    def unwrap_msg(self, msg: bytes) -> int:
        return struct.unpack('>I', msg)[0]

    def read(self, sock: socket) -> bytes:
        # reads prefix (4 bytes int) then reads full msg
        hlen = 4
        raw_msglen = self.recvall(sock, hlen)
        if not raw_msglen:
            raise SocketReadError
        msglen = self.unwrap_msg(raw_msglen)
        full_msg = self.recvall(sock, msglen)
        if not full_msg:
            raise SocketReadError
        return full_msg

    def recvall(self, sock: socket, n: int) -> bytes:
        self.logger.debug("Reading from socket {} bytes".format(n))
        data = b''
        while len(data) < n:
            packet = sock.recv(n - len(data))
            if not packet:
                raise SocketWriteError
            data += packet
        self.logger.debug("Reading from socket completed successfully")
        return data

    def write(self, sock: socket, msg: bytes) -> None:
        self.logger.debug("Writing to socket {} bytes".format(len(msg)))
        wrapped_msg = self.wrap_msg(msg)
        sock.sendall(wrapped_msg)  # sends entire buffer or raises exception
        self.logger.debug("Writing to socket completed successfully")


# ---------------------------------------------------------------------------
# Socket Exceptions
# Thrown on socket level and propagates to client/server
# ---------------------------------------------------------------------------

class SocketException(RuntimeError):

    def __init__(self, *args: object) -> None:
        super().__init__(*args)


class SocketReadError(SocketException):
    DEFAULT = "Error reading from socket"

    def __init__(self, message: str = DEFAULT) -> None:
        super().__init__(message)


class SocketWriteError(SocketException):
    DEFAULT = "Error writing to socket"

    def __init__(self, message: str = DEFAULT) -> None:
        super().__init__(message)


class StatusCode(Enum):
    OK = 1,
    ERR = 2


# ---------------------------------------------------------------------------
# Common data class with common static methods
# Mostly for parsing / validation:
# ---------------------------------------------------------------------------
class Utils:
    # CONSTANTS:
    ALLOWED_CMDS = ['ENQ', 'DEQ', 'DEBUG', 'STAT', 'STOP', 'EXIT']
    ALLOWED_DEBUG_MODES = ['on', 'off']
    IP_PORT_REGEX = r'[0-9]+(?:\.[0-9]+){3}:[0-9]+'
    # CONFIGURATION DATA: (move to configuration file)
    HOST, PORT = '127.0.0.1', 301
    TIMEOUT = 1
    MAX_CLIENTS = 100

    @staticmethod
    def validate_input(in_read: list) -> bool:
        if len(in_read) < 1 or len(in_read) > 2 or in_read[0] not in Utils.ALLOWED_CMDS:
            return False
        if len(in_read) == 2:
            if in_read[0] == "ENQ":
                return Utils.is_json(in_read[1])
            if in_read[0] == "DEBUG":
                return in_read[1] in Utils.ALLOWED_DEBUG_MODES
            return False
        return True

    @staticmethod
    def is_json(j):
        try:
            json.loads(j)
        except ValueError:
            return False
        return True

    @staticmethod
    def validate_launch(args, typez: str):
        if len(args) != 3 or args[1] != typez or not re.findall(Utils.IP_PORT_REGEX, args[2]):
            print("Usage: <{} addr:port>".format(typez))
            exit(0)

    @staticmethod
    def json_decode(json_bytes: bytes, encoding="utf-8"):
        json_str = json_bytes.decode(encoding).replace("'", '"')  # b'{...}'
        return json.loads(json_str)

    @staticmethod
    def json_encode(obj, encoding="utf-8") -> bytes:
        return json.dumps(obj).encode(encoding)
