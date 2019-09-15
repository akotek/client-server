import json
import struct
import sys, logging.config
import uuid
from socket import socket

from utils import Utils

logging.config.fileConfig('logging.conf')
logger = logging.getLogger('Client')


class Client:

    def __init__(self, addr: tuple):
        self.connection_details = addr
        self.uid = str(uuid.uuid4().int)

    def connect(self):
        self.socket = socket()
        self.socket.connect(self.connection_details)
        self.socket.settimeout(Utils.TIMEOUT)
        logger.info("Client connected successfully to {}".format(self.connection_details))

    @staticmethod
    def parse_command(s: list) -> dict:
        logger.debug("Parsing given string {} to command".format(s))
        type, payload = s[0], None
        if len(s) == 2:
            payload = json.loads(s[1])
        request = {
            "type": type,
            "payload": payload
        }
        return request

    def read(self) -> dict:
        # first read 4 bytes, then read the needed size:
        raw_msglen = self.recvall(self.socket, 4)
        if not raw_msglen:
            return None
        msglen = struct.unpack('>I', raw_msglen)[0]
        msg_bytes = self.recvall(self.socket, msglen)
        if not msg_bytes:
            raise Exception(".......take care later....")
        return Utils.json_decode(msg_bytes)

    def write(self, msg: bytes) -> None:
        # add message size as prefix (int 4bytes):
        logger.debug("Sending message of size {}".format(len(msg)))
        msg = struct.pack('>I', len(msg)) + msg
        self.socket.sendall(msg)

    def recvall(self, sock: socket, n: int) -> bytes:
        logger.debug("Reading from socket {} bytes".format(n))
        data = b''
        while len(data) < n:
            packet = sock.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data

    def close_connection(self):
        con_name = self.get_name()
        logger.debug("Closing connection for {}".format(con_name))
        self.socket.close()
        logger.info("Closed connection successfully for {}".format(con_name))

    def get_name(self):
        return '(' + str(self.uid[0:2]) + ')'


def run():
    Utils.validate_launch(sys.argv, "client")
    host, port = sys.argv[2].split(":")
    client = Client(addr=(host, int(port)))

    while True:
        in_read = input("Enter wanted command\n")
        if not Utils.validate_input(in_read.split()):
            print("Wrong stdin command entered")
            continue

        client.connect()
        request = client.parse_command(in_read.split(" ", 1))
        client.write(Utils.json_encode(request))
        logger.info("Client {} sent successfully command: {}".format(client.get_name(), request))
        response = client.read()
        logger.info("Client {} received successfully response {}\n from server".format(client.get_name(), response))
        client.close_connection()


if __name__ == '__main__':
    run()
