#!/usr/bin/python3


import json
import multiprocessing
import os
import signal
import sys
import time
from base64 import b64decode
from math import floor
from socket import socket

from Crypto.Cipher import AES
from pyDH import DiffieHellman
from twisted.internet import reactor
from twisted.internet.protocol import Protocol, Factory, connectionDone

from DBHandler import *


def get_transportable_data(packet) -> bytes:  # helper method to get a transportable version of non-encoded data
    return json.dumps(packet).encode()


running = True


class Server(Protocol):  # describes the protocol. compared to the client, the server has relatively little to do
    def __init__(self, factory):
        self.factory = factory
        self.endpoint_username = None  # describes the username of the connected user
        self.key = None
        self.receiving_file = False
        self.outgoing = None
        self.buffer = b""
        self.ready_to_receive = False
        self.daemons = []
        signal.signal(signal.SIGINT, self.terminator)

    def ack(self, packet, speed):
        self.factory.connections[packet['sender']].transport.write("a".encode())

    def terminator(self, *args, **kwargs):
        for process in self.daemons:
            process.kill()
        reactor.stop()
        return

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

    # noinspection PyArgumentList
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
                    self.factory.connections[packet['sender']]
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
                            sock = socket()
                            sock.bind(("0.0.0.0", 0))
                            i['address'] = sock.getsockname()[0]
                            i['port'] = sock.getsockname()[1]
                            i['content'] = None
                            p = multiprocessing.Process(target=self.sender_daemon, args=(sock, i))
                            self.daemons.append(p)
                            p.start()
                            self.factory.connections[packet['sender']].transport.write(get_transportable_data(i))
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

        elif packet['command'] == 'call':
            try:
                packet['address'] = self.factory.connections[packet['sender']].transport.getPeer().host
                self.factory.connections[packet['destination']].transport.write(get_transportable_data(packet))
            except KeyError:
                reply = {
                    'sender': 'SERVER',
                    'command': 'call_fail'
                }
                self.transport.write(get_transportable_data(reply))

        elif packet['command'] == 'prepare_for_file':
            port = packet['port']
            sender_address = str(self.factory.connections[packet['sender']].transport.getPeer().host)

            try:
                transport = self.factory.connections[packet['destination']].transport
                sock = socket()
                sock.bind(("0.0.0.0", 0))
                p = multiprocessing.Process(target=self.forwarder_daemon, args=((sender_address, port), sock,))
                self.daemons.append(p)
                p.start()
                packet['port'] = sock.getsockname()[1]
                transport.write(get_transportable_data(packet))
            except KeyError:
                p = multiprocessing.Process(
                    target=self.receiver_daemon, args=(packet, sender_address, port, self.ack, )
                )
                self.daemons.append(p)
                p.start()
        else:
            reply = {
                'sender': 'SERVER',
                'command': '400'
            }
            self.transport.write(get_transportable_data(reply))

    @staticmethod
    def receiver_daemon(packet, sender_address, port, callback):
        chunk_size = 2 ** 29
        packet['filename'] = packet['filename'].replace('/', '[SLASH]')
        packet['filename'] = packet['filename'].replace('\\', '[BACKSLASH]')
        try:
            # print(f"{path}/cache/{packet['filename']}")
            f = open(f"{path}/cache/{packet['filename']}", 'wb+')
        except FileNotFoundError:
            makedirs(f'{path}/cache')
            f = open(f"{path}/cache/{packet['filename']}", 'wb+')

        sock = socket()
        # print(sender_address, port)
        sock.connect((sender_address, int(port)))
        start = time.time()
        chunk = sock.recv(chunk_size)
        while chunk:
            f.write(chunk)
            chunk = sock.recv(chunk_size)
        sock.send("OK".encode())
        sock.close()
        end = time.time()
        packet['isfile'] = True
        speed = floor(packet['file_size'] / 1000000 / (end - start + 0.01) * 8)
        print(
            f"Transfer rate is {speed} mbps")
        packet['content'] = packet['filename']
        add_message_to_cache(packet)
        callback(packet, speed)

    @staticmethod
    def forwarder_daemon(sender, sock):
        global running
        chunk_size = 2 ** 29

        sock.listen()

        outgoing = socket()
        while True:
            try:
                outgoing.connect(sender)
            except ConnectionRefusedError:
                pass
            else:
                break
        print(f"Connected to sender! He is {outgoing.getpeername()}")

        while running:
            try:
                client_socket, addr = sock.accept()
                print(f"Connected to destination! He is {client_socket.getpeername()}")
            except BlockingIOError:
                pass
            else:
                start = time.time()
                chunk = outgoing.recv(chunk_size)
                while chunk:
                    client_socket.send(chunk)
                    chunk = outgoing.recv(chunk_size)
                client_socket.close()
                sock.close()
                outgoing.close()
                end = time.time()
                return
        return

    @staticmethod
    def sender_daemon(sock, packet):
        sock.listen()
        while running:
            try:
                client_socket, address = sock.accept()
                print(f"Connected to destination! He is {client_socket.getpeername()}")
            except BlockingIOError:
                pass
            else:
                start = time.time()
                with open(f"{path}/cache/{packet['filename']}", "rb") as f:
                    client_socket.sendfile(f, 0)
                sock.close()
                client_socket.close()
                end = time.time()
                # print(end - start)
                os.remove(f.name)
                return
        return

    def dataReceived(self, data):
        data = data.split('\r\n'.encode())
        logging.info(data)
        for message in data:
            if message:
                self.decode_command(message)


class ServerFactory(Factory):
    def __init__(self):
        self.connections = dict()
        self.mode = None

    def buildProtocol(self, address):
        return Server(self)


if __name__ == '__main__':
    reactor.listenTCP(8123, ServerFactory())
    logging.info("Server started.")
    reactor.run()
