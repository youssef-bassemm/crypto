from __future__ import annotations
import socket
import struct

from des import BLOCK_SIZE, ecb_decrypt, ecb_encrypt, pkcs7_pad


HOST = "127.0.0.1"
PORT = 5050
SHARED_KEY: bytes = b"LGCYBANK"

assert len(SHARED_KEY) * 8 == 64, "DES key must be exactly 64 bits"


def des_encrypt(plaintext: bytes) -> bytes:
    return ecb_encrypt(plaintext, SHARED_KEY)


def des_decrypt(ciphertext: bytes) -> bytes:
    return ecb_decrypt(ciphertext, SHARED_KEY)


def pad(data: bytes) -> bytes:
    return pkcs7_pad(data, BLOCK_SIZE)


def send_msg(sock: socket.socket, payload: bytes) -> None:
    sock.sendall(struct.pack("!I", len(payload)) + payload)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed before the full message arrived")
        buf += chunk
    return buf


def recv_msg(sock: socket.socket) -> bytes:
    (length,) = struct.unpack("!I", _recv_exact(sock, 4))
    return _recv_exact(sock, length)


def split_blocks(data: bytes) -> list[bytes]:
    return [data[i:i + BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]


def _printable(block: bytes) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "." for b in block)


def print_block_table(ciphertext: bytes, padded_plaintext: bytes | None = None) -> None:
    ct_blocks = split_blocks(ciphertext)
    pt_blocks = split_blocks(padded_plaintext) if padded_plaintext else [b""] * len(ct_blocks)
    first_seen: dict[bytes, int] = {}
    if padded_plaintext:
        print("  Blk | Plaintext  | Plaintext (hex)  | Ciphertext (hex)")
        print("  ----+------------+------------------+-----------------")
    else:
        print("  Blk | Ciphertext (hex)")
        print("  ----+-----------------")
    for i, (pt, ct) in enumerate(zip(pt_blocks, ct_blocks), start=1):
        note = ""
        if ct in first_seen:
            note = f"  <== IDENTICAL to block {first_seen[ct]}"
        else:
            first_seen[ct] = i
        if padded_plaintext:
            print(f"  {i:>3} | {_printable(pt):<10} | {pt.hex().upper()} | {ct.hex().upper()}{note}")
        else:
            print(f"  {i:>3} | {ct.hex().upper()}{note}")
