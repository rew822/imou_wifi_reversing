#!/usr/bin/env python3
"""
IMOU Camera WiFi Configuration Tool
Based on the captured legacy C1/83 hybrid-encryption protocol

Protocol Flow:
1. Discovery via UDP (DHIP)
2. TCP connection to port 37777
3. Request RSA public key from camera
4. RSA-wrap a random AES key and AES-encrypt the legacy WiFi structure
5. Send encrypted config
"""

import socket
import struct
import json
import base64
import os
import sys
import argparse
from typing import Optional, Tuple

try:
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("[!] Warning: cryptography module not available")
    print("[!] Install with: pip3 install cryptography")


class ImouWiFiConfig:
    """IMOU Camera WiFi Configuration using Dahua DHIP Protocol"""

    TCP_PORT = 37777
    UDP_PORT = 37810

    # Protocol constants
    MAGIC_REQUEST = 0xa3
    MAGIC_RESPONSE = 0xb3
    MAGIC_WIFI_REQUEST = 0xc1

    CMD_CONFIG = b"config"
    SUBCMD_WIFI_SCAN = 0x87
    SUBCMD_GET_RSA = 0xaa  # Get RSA key (CORRECTED!)
    SUBCMD_SET_WIFI = 0x83  # Set WiFi (after getting RSA)

    def __init__(self, camera_ip: str, timeout: int = 10):
        self.camera_ip = camera_ip
        self.timeout = timeout
        self.session_id = 1  # RSA request value at header offset 28

    def _build_tcp_packet(self, magic: int, command: bytes, subcommand: int,
                          payload: bytes = b"") -> bytes:
        """Build TCP protocol packet for port 37777"""

        # Two different packet formats:
        # 1. Simple request (magic 0xa3): 32 bytes, no length field
        # 2. WiFi config (magic 0xc1): has length field at offset 4

        if magic == 0xc1:  # WiFi config format
            # Structure:
            # 0x00: magic (1 byte)
            # 0x01-03: padding (3 bytes)
            # 0x04-07: payload length (4 bytes, little-endian)
            # 0x08-0f: command (8 bytes)
            # 0x10-13: subcommand (4 bytes)
            # 0x14-17: padding (4 bytes)
            # 0x18-1b: RSA ciphertext byte length (4 bytes)
            # 0x1c-1f: padding (4 bytes)
            # 0x20+: payload

            packet = bytearray(32)
            packet[0] = magic
            packet[4:8] = struct.pack("<I", len(payload))
            packet[8:8+len(command)] = command
            packet[16:20] = struct.pack("<I", subcommand)
            # For C1/83 this is the binary RSA ciphertext length, not a session.
            packet[24:28] = struct.pack("<I", 256)

            return bytes(packet) + payload

        else:  # Simple request format (0xa3, 0xb3)
            # Structure from packet analysis:
            # 0x00: magic (1 byte)
            # 0x01-07: padding (7 bytes)
            # 0x08-17: command (16 bytes)
            # 0x10: subcommand (1 byte) - overlaps with command padding!
            # 0x1c: session_id (1 byte)
            # 0x20+: payload

            packet = bytearray(32)
            packet[0] = magic
            packet[8:8+len(command)] = command
            packet[16] = subcommand
            packet[28] = self.session_id & 0xFF

            return bytes(packet) + payload

    def _send_tcp_command(self, magic: int, command: bytes, subcommand: int,
                          payload: bytes = b"") -> Optional[bytes]:
        """Send TCP command and receive response"""

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.camera_ip, self.TCP_PORT))

            # Build and send packet
            packet = self._build_tcp_packet(magic, command, subcommand, payload)
            print(f"[>] Sending {len(packet)} bytes to {self.camera_ip}:{self.TCP_PORT}")
            print(f"    Magic: 0x{magic:02x}, Command: {command.decode('ascii', errors='ignore').rstrip(chr(0))}, Subcommand: 0x{subcommand:02x}")
            sock.sendall(packet)

            # Receive response
            response = sock.recv(4096)
            print(f"[<] Received {len(response)} bytes")

            sock.close()
            return response

        except Exception as e:
            print(f"[-] TCP command failed: {e}")
            return None

    def get_rsa_public_key(self) -> Optional[Tuple[int, int]]:
        """
        Request RSA public key from camera
        Returns (modulus, exponent) tuple
        """
        print("\n[*] Requesting RSA public key from camera...")

        response = self._send_tcp_command(
            self.MAGIC_REQUEST,
            self.CMD_CONFIG,
            self.SUBCMD_GET_RSA,
            b""
        )

        if not response or len(response) < 100:
            print("[-] Failed to get RSA key")
            return None

        # Extract JSON from response
        try:
            # Find JSON in response
            json_start = response.find(b'{"asymmetric"')
            if json_start == -1:
                print("[-] No RSA key in response")
                return None

            json_end = response.find(b'}', json_start) + 1
            json_data = response[json_start:json_end]

            data = json.loads(json_data.decode('utf-8'))

            # Parse N and E
            pub_parts = data['pub'].split(',')
            n_hex = pub_parts[0].split(':')[1]
            e_hex = pub_parts[1].split(':')[1]

            modulus = int(n_hex, 16)
            exponent = int(e_hex, 16)

            print(f"[+] Got RSA public key")
            print(f"    Modulus: {n_hex[:40]}...{n_hex[-40:]}")
            print(f"    Exponent: {e_hex}")
            print(f"    Cipher: {data.get('cipher', [])}")

            return (modulus, exponent)

        except Exception as e:
            print(f"[-] Failed to parse RSA key: {e}")
            return None

    @staticmethod
    def _build_wifi_plaintext(ssid: str, password: str,
                              encryption: int) -> bytes:
        """Build the legacy 200-byte NET_IN_SET_DEV_WIFI wire structure."""
        ssid_bytes = ssid.encode("utf-8")
        password_bytes = password.encode("utf-8")
        if len(ssid_bytes) > 35:
            raise ValueError("SSID is longer than 35 UTF-8 bytes")
        if len(password_bytes) > 127:
            raise ValueError("password is longer than 127 UTF-8 bytes")
        if not 0 <= encryption <= 0xFFFFFFFF:
            raise ValueError("encryption must be an unsigned 32-bit integer")

        plaintext = bytearray(200)
        plaintext[4:4 + len(ssid_bytes)] = ssid_bytes
        plaintext[56:56 + len(password_bytes)] = password_bytes
        struct.pack_into("<I", plaintext, 184, encryption)
        plaintext[188] = 1
        return bytes(plaintext)

    def encrypt_wifi_data(self, ssid: str, password: str, encryption: int,
                          modulus: int, exponent: int,
                          aes_key: Optional[bytes] = None) -> Optional[bytes]:
        """
        Encrypt WiFi credentials with RSA public key
        Returns encrypted data ready to send
        """

        if not CRYPTO_AVAILABLE:
            print("[-] Cryptography module not available")
            return None

        print(f"\n[*] Encrypting WiFi credentials...")
        print(f"    SSID: {ssid}")
        print(f"    Password: {'*' * len(password)}")

        try:
            plaintext = self._build_wifi_plaintext(ssid, password, encryption)
            aes_key = aes_key or os.urandom(16)
            if len(aes_key) != 16:
                raise ValueError("AES key must be exactly 16 bytes")

            # Build RSA public key
            public_numbers = rsa.RSAPublicNumbers(exponent, modulus)
            public_key = public_numbers.public_key(default_backend())

            rsa_ciphertext = public_key.encrypt(aes_key, padding.PKCS1v15())
            if len(rsa_ciphertext) != 256:
                raise ValueError("camera RSA key is not 2048 bits")

            # The SDK uses zero padding: 200 bytes become 13 AES blocks.
            padded_plaintext = plaintext + b"\x00" * 8
            encryptor = Cipher(algorithms.AES(aes_key), modes.ECB()).encryptor()
            aes_ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

            rsa_hex = rsa_ciphertext.hex().upper().encode("ascii")
            payload = (b"AES-128\r\n" + struct.pack("<H", len(rsa_hex)) +
                       rsa_hex + base64.b64encode(aes_ciphertext) + b"\x00")
            if len(payload) != 804:
                raise ValueError(f"unexpected encrypted payload size: {len(payload)}")

            print(f"[+] Built hybrid encrypted payload: {len(payload)} bytes")

            return payload

        except Exception as e:
            print(f"[-] Encryption failed: {e}")
            import traceback
            traceback.print_exc()
            return None

    def set_wifi(self, ssid: str, password: str, encryption: int) -> bool:
        """
        Configure WiFi on camera
        Full flow: get RSA key -> encrypt credentials -> send config
        All on the SAME TCP connection!
        """

        print(f"\n[*] Connecting to camera...")

        try:
            # Open ONE TCP connection for everything
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.camera_ip, self.TCP_PORT))
            print(f"[+] Connected to {self.camera_ip}:{self.TCP_PORT}")

            # Step 1: Get RSA public key (on this connection)
            print(f"\n[*] Requesting RSA public key...")

            rsa_packet = self._build_tcp_packet(
                self.MAGIC_REQUEST,
                self.CMD_CONFIG,
                self.SUBCMD_GET_RSA,
                b""
            )

            sock.sendall(rsa_packet)
            print(f"[>] Sent RSA request ({len(rsa_packet)} bytes)")

            rsa_response = sock.recv(4096)
            print(f"[<] Received {len(rsa_response)} bytes")

            # Parse RSA key
            if b'asymmetric' not in rsa_response:
                print("[-] No RSA key in response")
                sock.close()
                return False

            json_start = rsa_response.find(b'{"asymmetric"')
            json_end = rsa_response.find(b'}', json_start) + 1
            json_data = rsa_response[json_start:json_end]

            data = json.loads(json_data.decode('utf-8'))
            pub_parts = data['pub'].split(',')
            n_hex = pub_parts[0].split(':')[1]
            e_hex = pub_parts[1].split(':')[1]

            modulus = int(n_hex, 16)
            exponent = int(e_hex, 16)

            print(f"[+] Got RSA public key")

            # Step 2: Encrypt WiFi data
            encrypted_payload = self.encrypt_wifi_data(
                ssid, password, encryption, modulus, exponent
            )
            if not encrypted_payload:
                sock.close()
                return False

            # Step 3: Send encrypted WiFi config (on SAME connection!)
            print(f"\n[*] Sending WiFi configuration...")

            wifi_packet = self._build_tcp_packet(
                self.MAGIC_WIFI_REQUEST,
                self.CMD_CONFIG,
                self.SUBCMD_SET_WIFI,
                encrypted_payload
            )

            sock.sendall(wifi_packet)
            print(f"[>] Sent WiFi config ({len(wifi_packet)} bytes)")

            # Wait for response
            try:
                sock.settimeout(5)  # Give it time to respond
                wifi_response = sock.recv(4096)
                print(f"[<] Received {len(wifi_response)} bytes")

                # Parse response
                if len(wifi_response) >= 4:
                    status_byte = wifi_response[3]
                    print(f"[*] Status code: 0x{status_byte:02x} ({status_byte})")

                    if status_byte == 0x78:
                        print(f"[+] Status 0x78 - SUCCESS")
                        sock.close()
                        return True
                    else:
                        print(f"[!] Unknown status: 0x{status_byte:02x}")

            except socket.timeout:
                print(f"[-] No response; acceptance cannot be confirmed")

            sock.close()

            return False

        except Exception as e:
            print(f"[-] Error: {e}")
            import traceback
            traceback.print_exc()
            return False


def main():
    parser = argparse.ArgumentParser(
        description='IMOU Camera WiFi Configuration Tool',
        epilog='''
Examples:
  # Configure WiFi
  %(prog)s --ip 192.168.0.108 --ssid "MyWiFi" --password "MyPassword123" --encryption 9

  # Get RSA key only (test)
  %(prog)s --ip 192.168.0.108 --test-rsa
        '''
    )

    parser.add_argument('--ip', required=True, help='Camera IP address')
    parser.add_argument('--ssid', help='WiFi SSID to configure')
    parser.add_argument('--password', help='WiFi password')
    parser.add_argument('--encryption', type=int,
                        help='scan-derived combined WiFi encryption value')
    parser.add_argument('--test-rsa', action='store_true',
                       help='Only test RSA key retrieval')

    args = parser.parse_args()

    if not CRYPTO_AVAILABLE and not args.test_rsa:
        print("[-] Cryptography module required for WiFi configuration")
        print("[-] Install with: sudo apt install python3-cryptography")
        return 1

    config = ImouWiFiConfig(args.ip)

    # Test RSA only
    if args.test_rsa:
        rsa_key = config.get_rsa_public_key()
        if rsa_key:
            print("\n[+] RSA key retrieval successful!")
            return 0
        else:
            print("\n[-] RSA key retrieval failed")
            return 1

    # Configure WiFi
    if not args.ssid or args.password is None or args.encryption is None:
        parser.error("--ssid, --password, and --encryption are required")

    success = config.set_wifi(args.ssid, args.password, args.encryption)

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
