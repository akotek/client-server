import json
import re
import socket
import struct


class SocketUtils:

    # Class for common operations on socket object,
    # used by both Server and Client

    @staticmethod
    def wrap_msg(msg: bytes) -> bytes:
        return struct.pack('>I', len(msg)) + msg

    @staticmethod
    def unwrap_msg(msg: bytes) -> int:
        return struct.unpack('>I', msg)[0]

    @staticmethod
    def recvall(sock: socket, n: int) -> bytes:
        data = b''
        while len(data) < n:
            packet = sock.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data


class Utils:
    # CONSTANTS:
    ALLOWED_CMDS = ['ENQ', 'DEQ', 'DEBUG', 'STAT', 'STOP', 'EXIT']
    ALLOWED_DEBUG = ['on', 'off']
    IP_PORT_REGEX = r'[0-9]+(?:\.[0-9]+){3}:[0-9]+'
    # CONFIGURATION DATA: (move to configuration file)
    HOST, PORT = '127.0.0.1', 301
    TIMEOUT = 2
    MAX_CLIENTS = 100

    @staticmethod
    def validate_input(in_read: list) -> bool:
        if 1 > len(in_read) > 2 or in_read[0] not in Utils.ALLOWED_CMDS:
            return False
        if len(in_read) == 2 and in_read[1] not in Utils.ALLOWED_DEBUG and not Utils.is_json(in_read[1]):
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


class SocketReadError(RuntimeError):
    DEFAULT = "Error reading from socket"

    def __init__(self, message: str = DEFAULT) -> None:
        super().__init__(message)