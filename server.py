from __future__ import annotations
import argparse
import socket

from des_common import (HOST, PORT, des_decrypt, des_encrypt, print_block_table,
                        recv_msg, send_msg)


def handle_client(conn: socket.socket) -> None:
    ciphertext = recv_msg(conn)
    print(f"[SERVER] Received {len(ciphertext)} bytes of ciphertext:")
    print_block_table(ciphertext)
    try:
        plaintext = des_decrypt(ciphertext)
    except ValueError:
        print("[SERVER] !! Decryption failed: wrong key or corrupted ciphertext")
        return
    print(f"[SERVER] Decrypted transaction: {plaintext.decode('utf-8', errors='replace')}")
    send_msg(conn, des_encrypt(b"ACK: transaction received by Legacy Bank mainframe"))


def main() -> None:
    parser = argparse.ArgumentParser(description="Legacy Bank DES-ECB server")
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    args = parser.parse_args()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((args.host, args.port))
        srv.listen()
        srv.settimeout(1.0)
        print(f"[SERVER] Legacy Bank mainframe listening on {args.host}:{args.port}"
              "  (DES-ECB, static 64-bit key)")
        print("[SERVER] Press Ctrl+C to stop.\n")
        try:
            while True:
                try:
                    conn, addr = srv.accept()
                except socket.timeout:
                    continue
                with conn:
                    conn.settimeout(10.0)
                    print(f"[SERVER] Connection from {addr[0]}:{addr[1]}")
                    try:
                        handle_client(conn)
                    except (ConnectionError, socket.timeout) as exc:
                        print(f"[SERVER] !! Connection problem: {exc}")
                    print("-" * 72)
        except KeyboardInterrupt:
            print("\n[SERVER] Shutting down.")


if __name__ == "__main__":
    main()