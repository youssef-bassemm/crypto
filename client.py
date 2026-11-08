from __future__ import annotations
import argparse
import socket

from des_common import (BLOCK_SIZE, HOST, PORT, SHARED_KEY, des_decrypt, des_encrypt,
                        pad, print_block_table, recv_msg, send_msg)

DEFAULT_TXN = "TRANSFER|FROM=ACC-1001|TO=ACC-2002|AMT=500.00|CUR=EGP"
ECB_DEMO_TXN = "PAY 500 " * 2


def main() -> None:
    parser = argparse.ArgumentParser(description="Legacy Bank DES-ECB client")
    parser.add_argument("message", nargs="?", default=DEFAULT_TXN)
    parser.add_argument("--ecb-demo", action="store_true",
                        help="send two identical plaintext blocks (Appendix B)")
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    args = parser.parse_args()
    message = ECB_DEMO_TXN if args.ecb_demo else args.message
    plaintext = message.encode("utf-8")
    ciphertext = des_encrypt(plaintext)
    print(f"[CLIENT] Legacy Bank mobile app | DES-ECB | key = "
          f"{SHARED_KEY.hex().upper()} (\"{SHARED_KEY.decode()}\")")
    print(f"[CLIENT] Plaintext ({len(plaintext)} bytes): {message!r}")
    print(f"[CLIENT] After PKCS#7 padding: {len(ciphertext)} bytes = "
          f"{len(ciphertext) // BLOCK_SIZE} DES blocks\n")
    print_block_table(ciphertext, pad(plaintext))
    with socket.create_connection((args.host, args.port), timeout=10) as sock:
        send_msg(sock, ciphertext)
        print(f"\n[CLIENT] Sent {len(ciphertext)} bytes of ciphertext to {args.host}:{args.port}")
        reply = des_decrypt(recv_msg(sock))
        print(f"[CLIENT] Server reply (decrypted): {reply.decode()}")


if __name__ == "__main__":
    main()