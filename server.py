#!/usr/bin/python3


import json
from base64 import b64decode
from socket import socket

from Crypto.Cipher import AES
from pyDH import DiffieHellman
from twisted.internet import reactor
from twisted.internet.protocol import Protocol, Factory, connectionDone
from sys import getsizeof
from io import BytesIO
from twisted.protocols.basic import FileSender
from twisted.internet.defer import Deferred
from DBHandler import *


def get_transportable_data(packet) -> bytes:  # helper method to get a transportable version of non-encoded data
    return json.dumps(packet).encode()


class Server(Protocol):  # describes the protocol. compared to the client, the server has relatively little to do
    def __init__(self, factory):
        self.factory = factory
        self.endpoint_username = None  # describes the username of the connected user
        self.key = None
        self.receiving_file = False
        self.outgoing = None
        self.buffer = b""
        self.ready_to_receive = False

    def connectionMade(self):
        pass

    def connectionLost(self, reason=connectionDone):
        if self.endpoint_username is not None:
            logging.info(self.endpoint_username + " logged out.")
            try:
                del self.factory.connections[self.endpoint_username]
            except KeyError:
                pass
            self.endpoint_username = None

    def decode_command(self, data):
        try:
            packet = json.loads(data)
        except UnicodeError:
            return
        except Exception as e:
            logging.error(f"Tried loading, failed! Reason: {e}")
            logging.error(f"Message contents was: {data}")
            logging.error("Connection forced closed.")
            self.transport.loseConnection()
            return

        if packet['command'] == 'secure':
            private = DiffieHellman()
            public = private.gen_public_key()
            reply = {
                'sender': 'SERVER',
                'command': 'secure',
                'content': public
            }
            self.transport.write(get_transportable_data(reply))
            self.key = private.gen_shared_key(packet['key'])

        elif packet['command'] == 'login':
            cipher = AES.new(self.key.encode(), AES.MODE_SIV)
            encrypted = b64decode(packet['password'].encode())
            tag = b64decode(packet['tag'].encode())
            password = cipher.decrypt_and_verify(encrypted, tag)
            if login(packet['sender'], password):
                try:
                    t = self.factory.connections[packet['sender']]
                except KeyError:
                    pass
                else:
                    self.transport.loseConnection()
                logging.info(f"{packet['sender']} logged in.")
                self.factory.connections[packet['sender']] = self
                self.endpoint_username = packet['sender']
                cached = get_cached_messages_for_user(packet['sender'])
                if cached:
                    for i in cached:
                        if i['command'] == 'prepare_for_file':
                            self.check_if_ready(i['sender'], i['destination'],
                                                i['timestamp'], i['content'], i['filename'])
                        else:
                            i['content'] = i['content'].decode()
                            self.factory.connections[packet['sender']].transport.write(get_transportable_data(i))
                reply = {
                    'sender': 'SERVER',
                    'command': '200'
                }
                self.transport.write(get_transportable_data(reply))
            else:
                reply = {
                    'sender': 'SERVER',
                    'command': '401'
                }
                self.transport.write(get_transportable_data(reply))

        elif packet['command'] == 'signup':
            cipher = AES.new(self.key.encode(), AES.MODE_SIV)
            encrypted = b64decode(packet['password'].encode())
            tag = b64decode(packet['tag'].encode())
            password = cipher.decrypt_and_verify(encrypted, tag)
            salt = bcrypt.gensalt()
            password = bcrypt.hashpw(password, salt)
            if add_user(packet['sender'], password, salt):
                reply = {
                    'sender': 'SERVER',
                    'command': '201'
                }
                self.transport.write(get_transportable_data(reply))
            else:
                reply = {
                    'sender': 'SERVER',
                    'command': '406'
                }
                self.transport.write(get_transportable_data(reply))

        elif packet['command'] == 'message' or \
                packet['command'] == 'friend_request' \
                or packet['command'] == 'friend_accept':
            try:
                self.factory.connections[packet['destination']].transport.write(get_transportable_data(packet))
            except KeyError:
                add_message_to_cache(packet)
                reply = {
                    'sender': 'SERVER',
                    'command': 'processed ok'
                }
                self.transport.write(get_transportable_data(reply))

        elif packet['command'] == 'prepare_for_file':
            port = packet['port']
            CHUNK_SIZE = 8 * 1024

            sock = socket()
            sock.connect((str(self.factory.connections[packet['sender']].transport.getPeer().host), int(port)))
            try:
                f = open(f".cache/{packet['filename']}", 'wb+')
            except FileNotFoundError:
                makedirs('.cache')
                f = open(f".cache/{packet['filename']}", 'wb+')
            packet['content'] = b''
            chunk = sock.recv(CHUNK_SIZE)
            while chunk:
                f.write(chunk)
                chunk = sock.recv(CHUNK_SIZE)
            sock.close()
            packet['isfile'] = True
            #add_message_to_cache(packet)


            """reply = {
                'sender': 'SERVER',
                'command': 'ready_for_file',
                'original_sender': packet['sender'],
                'original_destination': packet['destination'],
                'timestamp': packet['timestamp'],
            }
            
            logging.info(f"Opened f{self.fileSoceket.getsockname()[1]} for FT.")
            #self.receiving_file = True
            packet['isfile'] = True
            try:
                self.factory.connections[packet['destination']].outgoing = packet
            except KeyError:
                add_message_to_cache(packet)

            self.outgoing = packet
            self.transport.write(get_transportable_data(reply))"""

        elif packet['command'] == 'ready_for_file':
            logging.info(f"User {packet['sender']} reports ready to receive file")
            sender = FileSender()
            sender.CHUNK_SIZE = 2 ** 16
            blob = BytesIO(self.buffer)
            sender.beginFileTransfer(blob, self.factory.connections[packet['sender']].transport)
            self.buffer = b""
            self.outgoing = None
            logging.info(f"Finished upload to {packet['sender']}. {blob.getbuffer().nbytes} bytes transferred.")

        else:
            reply = {
                'sender': 'SERVER',
                'command': '400'
            }
            self.transport.write(get_transportable_data(reply))

    def check_if_ready(self, sender, peer, timestamp, data, filename):
        packet = {
            'sender': 'SERVER',
            'destination': peer,
            'command': 'prepare_for_file',
            'original_sender': sender,
            'timestamp': timestamp,
            'filename': filename
        }
        self.factory.connections[peer].buffer = data
        self.factory.connections[peer].transport.write(get_transportable_data(packet))

    def dataReceived(self, data):
        if not self.receiving_file:
            data = data.split('\r\n'.encode())
            logging.info(data)
            for message in data:
                if message:
                    self.decode_command(message)
        else:
            self.buffer += data
            if self.buffer[-2:] == '\r\n'.encode():
                logging.info(f"{self.endpoint_username} finished upload. {getsizeof(self.buffer)} bytes received.")
                self.receiving_file = False
                reply = {
                    'command': 'file_received',
                    'sender': 'SERVER'
                }
                self.transport.write(get_transportable_data(reply))
                try:
                    t = self.factory.connections[self.outgoing['destination']]
                    self.check_if_ready(self.outgoing['sender'], self.outgoing['destination'],
                                        self.outgoing['timestamp'], self.buffer, self.outgoing['filename'])
                except KeyError:
                    append_file_to_cache(self.outgoing, self.buffer)
                self.buffer = b""


class ServerFactory(Factory):
    def __init__(self):
        self.connections = dict()
        self.mode = None

    def buildProtocol(self, addr):
        return Server(self)


if __name__ == '__main__':
    reactor.listenTCP(8123, ServerFactory())
    logging.info("Server started.")
    reactor.run()
