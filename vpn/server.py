# This is the server side

import hashlib
import random
import socket
import threading
import logging
import rsa
from rsa import VerificationError
from utils import AuthResponse, AuthRequest, ConnResponse, ConnRequest, socket_recvall, decrypt_ct, encrypt_msg
from utils import socket_recvall, get_server_rsa_pk, get_server_rsa_sk, get_client_rsa_pk
from utils import nonce, socket_recvall
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import sys
import getopt

# set the log
logging.basicConfig(level=logging.INFO)

VALID_METHODS = {b'\x00': 'NO AUTHENTICATION REQUIRED'}
public_key = get_server_rsa_pk()
id_server = b'server'


class Socks5Server:

    def __init__(self, addr, pw, encryptor, method='tcp'):
        """
        Init the socks5 server
        :param addr: server address
        :param pw: password
        :param encryptor: encryption method, either AES-GCM or Chacha20Poly1305
        :param method: transport protocol, default TCP.
        """
        self.addr = addr
        self.s = None
        self.pw = pw
        self.encryptor = encryptor
        self.method = method.lower()
        if self.method not in ('tcp', 'udp'):
            raise ValueError('Only support TCP or UDP!')
        # bind
        if self.method == 'tcp':
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        elif self.method == 'udp':
            self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind(self.addr)

    def listen(self, unaccepted_pkg=0):
        """
        listen the port
        :param unaccepted_pkg: losing package to judge whether the connection could continue
        :return:
        """
        self.s.listen(unaccepted_pkg)
        while True:
            conn, addr = self.s.accept()
            thread = threading.Thread(target=(lambda c, a: Socks5ServerConn(c, a, self.addr, self.pw, self.encryptor)),
                                      args=(conn, addr))
            thread.start()

    def close(self):
        self.s.close()


class Socks5ServerConn:

    def __init__(self, s: socket.socket, client_addr, server_addr, pw, encryptor):
        """
        Initiate the Socks5 server connection object
        :param s: socket connection object
        :param client_addr: client address
        :param server_addr: server address
        :param pw: password
        :param encryptor: encryption method, either AES-GCM or Chacha20Poly1305
        """
        self.s = s
        self.addr = client_addr
        self.pw = pw
        self.encryptor = encryptor
        with self.s:
            if self.ake():
                logging.info(f'Connected by {client_addr}')
                if self.auth():
                    logging.info('  auth passed!')
                    dest = self.conn()
                    logging.info(f'  dest: {dest}')
                    if not dest:
                        self.s.sendall(ConnResponse(ConnResponse.REP_SOCKS_FAIL, server_addr).to_bytes())
                        return
                    self.s.sendall(ConnResponse(ConnResponse.REP_SUCCEEDED, server_addr).to_bytes())
                    logging.info('  send connection response')
                    self.forward(dest)


    def ake(self):
        """
        AKE implementation in server side.
        :return:
        """
        # server private key
        private_key = rsa.PrivateKey.load_pkcs1(get_server_rsa_sk())
        # receive data from client: (r, Sig(r), Cert_client)
        data = socket_recvall(self.s)
        len_cert_client = data[:2]
        # get r
        r = data[:38]
        # get client signature Sig(r)
        sig_client = data[38:294]
        # get Cert_client
        cert_client = data[294:]
        # check Cert_client
        id_client = cert_client[426:]
        if id_client != b'client':
            return False
        # Verify Sig(r)
        client_public_key = rsa.PublicKey.load_pkcs1(get_client_rsa_pk())
        try:
            rsa.verify(r, sig_client, client_public_key)
        except VerificationError:
            return False
        # generate random number s
        s = random.randint(0, 1000000000000)
        s = s.to_bytes(length=38, byteorder=sys.byteorder)  # 38 bits
        # compute session key k
        k = hashlib.sha256(self.pw + id_server + id_client + id_server + r + s)
        # get ciphertext c
        c = AESGCM(k.digest()).encrypt(nonce, id_server, None)
        # get Sig(r, s, c, id_client)
        sig = rsa.sign(s + r + id_client + c, private_key, 'SHA-256')  # 256 bits
        # generate Cert_server
        cert = get_server_rsa_pk() + id_server  # 2 bytes to represent
        # send data to client: (s, c, Sig(r, s, c, id_client), Cert_server)
        len_cert = len(cert).to_bytes(length=2, byteorder=sys.byteorder)
        self.s.sendall(len_cert + s + sig + cert + c)
        self.pw = k.digest()
        logging.info(f'Server shared session key: {k.hexdigest()}')
        return True

    def auth(self):
        """
        Auth process in server side.
        :return: Is auth succeed or not.
        """
        req = AuthRequest.read(self.s)
        if req.ver != AuthRequest.VER_SOCKS5:
            logging.error("  Invalid prefix of SOCKS5!")
            return False
        for m in VALID_METHODS:
            if m in req.methods:
                logging.info("  Auth method: " + VALID_METHODS[m])
                self.s.sendall(AuthResponse(method=m).to_bytes())
                break
        else:
            logging.info("  No supported auth methods!")
            self.s.sendall(AuthResponse(method=AuthResponse.M_NO_SUPPORTED).to_bytes())
            return False
        return True

    def conn(self):
        """
        Connection process in server side.
        :return:
        """
        logging.info("Server starts to connect:")
        req = ConnRequest.read(self.s)

        if req.ver != ConnRequest.VER_SOCKS5:
            logging.error("  Invalid prefix of SOCKS5!")
            return
        if req.method == b'\x01':
            return req.dest
        elif req.method == b'\x02':
            logging.error("  Bind address is not supported!")
            return
        elif req.method == b'\x03':
            logging.error("  UDP is not supported now!")
            return

    def forward(self, dst):
        """
        Server forward the traffic to destination host
        :param dst:
        :return:
        """
        logging.info(f'  data from {dst}')
        req_data = socket_recvall(self.s)
        req_data = decrypt_ct(self.pw, req_data, self.encryptor)
        logging.info(f'  data:{req_data}')
        sock = socket.create_connection(dst)
        sock.sendall(req_data)
        msg = socket_recvall(sock)
        sock.close()
        logging.info(f'  msg:{msg}')
        msg = encrypt_msg(self.pw, msg, self.encryptor)
        self.s.sendall(msg)


def main(argv):
    """
    main function, the entrance of the program
    :param argv: command line parameters
    :return:
    """
    server_address = ''
    password = ''
    encryptor = ''
    opts, args = getopt.getopt(argv, 's:p:e:', ['server', 'password', 'encryptor'])
    for opt, arg in opts:
        if opt in ('-s', '--server'):
            server_address = arg
        elif opt in ('-p', '--password'):
            password = arg.encode('ascii')
        elif opt in ('-e', '--encryptor'):
            encryptor = arg
    server_split = server_address.split(':')
    server = Socks5Server(addr=('', int(server_split[1])), pw=password, encryptor=encryptor)
    server.listen()
    server.close()


if __name__ == '__main__':
    # to receive command line parameters
    main(sys.argv[1:])
