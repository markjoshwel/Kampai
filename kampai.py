"""
Kampai: A method of full-duplex, end-to-end encrypted, peer-to-peer secure communications.

This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <http://unlicense.org/>
"""

from typing import Optional, Tuple

from argparse import ArgumentParser
from urllib.parse import urlparse
from dataclasses import dataclass
from sys import stderr, stdout
from threading import Thread
from hashlib import md5
import socket

from nacl.public import PrivateKey, PublicKey, Box


@dataclass
class Behaviour:
    """
    Kampai Behavioural Data Structure

    creator: bool = True
        True if creator client
    target_host: Optional[str] = None
        ip address or hostname of peer, None for 'create' operation modes
    target_port: int = 450000
        port of peer
    client_host: str = "127.0.0.1"
        ip address or hostname of client
    client_port: int = 450000
        port of client
    """

    creator: bool = True
    target_host: Optional[str] = None
    target_port: int = 450000
    client_host: str = "127.0.0.1"
    client_port: int = 450000


class Client:
    __slots__: Tuple[str, ...] = (
        "sock",
        "behaviour",
        "peer_host",
        "peer_port",
        "self_skey",
        "peer_pkey",
        "box",
    )

    sock: socket.socket

    behaviour: Behaviour

    peer_host: str
    peer_port: int

    self_skey: PrivateKey
    peer_pkey: PublicKey

    box: Box

    def __init__(self, behaviour: Behaviour) -> None:
        """
        Instantiate a new Kampai Client object.
        """
        self.behaviour = behaviour
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self.sock.bind((self.behaviour.client_host, self.behaviour.client_port))
        self.self_skey = PrivateKey.generate()

        stderr.write(
            "kampai/prelude: {} client started on {}:{}\n".format(
                "creator" if self.behaviour.creator else "joiner",
                self.behaviour.client_host,
                self.behaviour.client_port,
            )
        )

        if not self.behaviour.creator:  # 'join' operation mode
            # TODO: messages are sending, now why isnt this working?
            establish = b"kampai_peer_establish:"
            pubkey = bytes(self.self_skey.public_key)
            self.sock.sendto(
                establish + pubkey,
                (self.behaviour.target_host, self.behaviour.target_port),
            )
            stderr.write(
                "kampai/prelude: attempting to connect with peer {}:{}\n".format(
                    self.behaviour.target_host, self.behaviour.target_port
                )
            )
            # stderr.write(f"establish={establish.hex()}, pubkey={pubkey.hex()}\n\n")

        waiting: bool = True

        while waiting:
            data, address = self.sock.recvfrom(4096)
            sdata: bytes = data.strip()

            if sdata.startswith(b"kampai_peer_establish:"):
                key = sdata[-32:]

                self.peer_host = address[0]
                self.peer_port = address[1]

                self.peer_pkey = PublicKey(public_key=key)
                self.box = Box(self.self_skey, self.peer_pkey)

                stderr.write(
                    "kampai/prelude: pubkey exchange (self={self}, peer={peer})\n".format(
                        self=(md5(bytes(self.self_skey.public_key)).digest().hex())[:7],
                        peer=(md5(key).digest().hex())[:7],
                    )
                )

                self.sock.sendto(
                    b"kampai_peer_establish:" + bytes(self.self_skey.public_key),
                    (self.peer_host, self.peer_port),
                )

                stderr.write(
                    f"kampai/prelude: kampai! peer is {self.peer_host}:{self.peer_port}\n"
                )
                waiting = False

        stderr.write("\n")

    def get_input(self) -> None:
        while True:
            message = input("kampai> ")

            encrypted: bytes = self.box.encrypt(message.encode("utf-8"))

            # print(f"[sent] {encrypted.hex()}")

            self.sock.sendto(
                encrypted,
                (self.peer_host, self.peer_port),
            )

    def run(self) -> None:
        input_mgr = Thread(target=self.get_input, daemon=True)
        input_mgr.start()

        while True:
            ciphertext = self.sock.recv(4096)

            try:
                # print(f"\n[recieved] {ciphertext.hex()}")
                plaintext = self.box.decrypt(ciphertext).decode("utf-8")

            except Exception as exc:
                # stdout.write(f"\r        \r!!!!!!! {exc.__class__.__name__}: {exc}\nkampai> ")
                pass

            else:
                stdout.write(f"\r        \r{plaintext}\nkampai> ")


def main():
    parser = ArgumentParser(
        prog="kampai",
        description="A method of peer-to-peer, end-to-end secure communications.",
    )

    parser.add_argument(
        "mode",
        default="create",
        const="create",
        nargs="?",
        choices=["create", "join"],
        help="operation mode",
    )

    parser.add_argument(
        "target_host",
        type=str,
        nargs="?",
        default=None,
        help="ip address or hostname of peers' client (only required for 'join' mode)",
    )

    parser.add_argument(
        "target_port",
        type=int,
        nargs="?",
        default=45000,
        help="specify peer port to use (defaults to 450000)",
    )

    parser.add_argument(
        "-ch",
        "--client_host",
        type=str,
        default="127.0.0.1",
        help="specify client ip address or hostname to use (defaults to '127.0.0.1')",
    )

    parser.add_argument(
        "-cp",
        "--client_port",
        type=int,
        default=45000,
        help="specify client port to use (defaults to 450000)",
    )

    args = parser.parse_args()

    creator: bool = False

    if args.mode == "create":
        creator = True

    else:  # args.mode == "join"
        if args.target_host is None:
            stderr.write(
                "kampai: operation mode 'join' requires the 'target_host' argument to be specified\n"
            )
            exit(-1)

    target_host: str = args.target_host
    if target_host is not None and "://" in target_host:
        _url = urlparse(target_host)
        target_host = socket.gethostbyname(_url.netloc)
        stderr.write(
            f"kampai/prelude: resolved target '{_url.geturl()}' to {target_host}\n"
        )

    client_host: str = args.client_host
    if "://" in client_host:
        _url = urlparse(client_host)
        client_host = socket.gethostbyname(_url.netloc)
        stderr.write(
            f"kampai/prelude: resolved client '{_url.geturl()}' to {client_host}\n"
        )

    behaviour: Behaviour = Behaviour(
        creator=creator,
        target_host=target_host,
        target_port=args.target_port,
        client_host=client_host,
        client_port=args.client_port,
    )

    client: Client = Client(behaviour=behaviour)
    client.run()


if __name__ == "__main__":
    main()
