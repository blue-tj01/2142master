#!/usr/bin/env python3
# FESL server end-to-end test: starts fesl_server with -X tls (Python's ssl
# module can't speak SSLv3) and logs in like the game does.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.

import os
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time

SERVER = sys.argv[1] if len(sys.argv) > 1 else "../src/server/fesl_server"
PING_INTERVAL = 1

# the client Hello and Login as captured in stuff/pcap
HELLO = ("TXN=Hello\nclientString=bf2142-pc\nsku=125170\nlocale=ru\nclientPlatform=PC\n"
         "clientVersion=1.10.112.0\nSDKVersion=2.8.0.1.0\nprotocolVersion=2.0\nfragmentSize=2048\n")
LOGIN = ("TXN=Login\nreturnEncryptedInfo=1\nname=Tema567\npassword={password}\n"
         "machineId=\nmacAddr=$1c6f65d226e4\n")

failures = 0


def check(cond, what):
    global failures
    if not cond:
        failures += 1
        print("FAIL:", what)


def encode(command, word, body):
    data = body.encode() + b"\0"
    return command.encode() + struct.pack(">II", word, 12 + len(data)) + data


class Client:
    def __init__(self, port):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers("ALL:@SECLEVEL=0")
        self.sock = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=10))
        self.buf = b""

    def send(self, command, word, body):
        self.sock.sendall(encode(command, word, body))

    def recv(self):
        while True:
            if len(self.buf) >= 12:
                size = struct.unpack(">I", self.buf[8:12])[0]
                if len(self.buf) >= size:
                    pkt, self.buf = self.buf[:size], self.buf[size:]
                    word = struct.unpack(">I", pkt[4:8])[0]
                    pairs = {}
                    for line in pkt[12:].rstrip(b"\0").decode().split("\n"):
                        if line:
                            k, _, v = line.partition("=")
                            pairs[k] = v
                    return pkt[:4].decode(), word, pairs
            data = self.sock.recv(65536)
            if not data:
                return None
            self.buf += data

    def close(self):
        self.sock.close()


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main():
    tmp = tempfile.mkdtemp()
    cert = os.path.join(tmp, "cert.pem")
    accounts = os.path.join(tmp, "accounts.txt")
    log = os.path.join(tmp, "server.log")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=fesl", "-keyout", cert, "-out", cert],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    with open(accounts, "w") as f:
        f.write("Tema567 123456 10\n")

    port = free_port()
    with open(log, "w") as logf:
        server = subprocess.Popen([SERVER, "-X", "tls", "-p", str(port), "-c", cert, "-a", accounts,
                                   "-i", str(PING_INTERVAL)], stdout=logf, stderr=subprocess.STDOUT)
    try:
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=1).close()
                break
            except OSError:
                time.sleep(0.1)

        # Hello, the server MemCheck and our answer to it
        c = Client(port)
        c.send("fsys", 0x80000001, HELLO)
        cmd, word, hello = c.recv()
        check((cmd, word, hello.get("TXN")) == ("fsys", 0x80000001, "Hello"), "Hello answer header")
        check(hello.get("domainPartition.subDomain") == "battlefield2142-2006", "Hello subDomain")
        check("%3a" in hello.get("curTime", ""), "Hello curTime format")
        cmd, word, memcheck = c.recv()
        check((cmd, word, memcheck.get("TXN")) == ("fsys", 0x80000001, "MemCheck"), "MemCheck from server")
        c.send("fsys", 0x80000000, "TXN=MemCheck\nresult=\n")

        # successful Login
        c.send("acct", 0x80000002, LOGIN.format(password="123456"))
        cmd, word, login = c.recv()
        check((cmd, word) == ("acct", 0x80000002), "Login answer header")
        check(login.get("displayName") == "Tema567" and login.get("userId") == "10", "Login account")
        check(len(login.get("lkey", "")) == 28 and "errorCode" not in login, "Login lkey")

        # keep-alive Ping after PING_INTERVAL seconds of silence
        start = time.time()
        cmd, word, ping = c.recv()
        check((cmd, word, ping.get("TXN")) == ("fsys", 0, "Ping"), "server Ping")
        check(time.time() - start >= PING_INTERVAL * 0.8, "Ping waited for the idle time")
        c.send("fsys", 0x80000000, "TXN=Ping\n")

        # not implemented yet
        c.send("subs", 0x80000003, "TXN=GetEntitlementByBundle\nbundleId=REG-PC-BF2142-UNLOCK-1\n")
        cmd, word, ent = c.recv()
        check((cmd, word, ent.get("errorCode")) == ("subs", 0x80000003, "99"), "not implemented error")

        # Goodbye closes the connection
        c.send("fsys", 0x80000004, "TXN=Goodbye\nreason=GOODBYE_CLIENT_NORMAL\n")
        check(c.recv() is None, "connection closed after Goodbye")
        c.close()

        # wrong password on a second connection
        c = Client(port)
        c.send("fsys", 0x80000001, HELLO)
        c.recv()
        c.recv()
        c.send("acct", 0x80000002, LOGIN.format(password="wrong-password"))
        cmd, word, login = c.recv()
        check(login.get("errorCode") == "122", "wrong password error")
        c.close()

        # the server is still alive, and never logs passwords
        check(server.poll() is None, "server still running")
    finally:
        server.terminate()
        server.wait(timeout=5)

    with open(log) as f:
        text = f.read()
    check("logged in as Tema567" in text, "login logged")
    check("123456" not in text and "wrong-password" not in text, "passwords not logged")
    if failures:
        print(text)
    print("server test:", "%d failures" % failures if failures else "ok")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
