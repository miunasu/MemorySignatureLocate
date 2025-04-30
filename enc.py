import sys
import os

key = 0x43

def xor_encrypt(data):
    return bytes(byte ^ key for byte in data)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python enc_make.py <shellcode_file>")
        sys.exit(1)

    shellcode_file = sys.argv[1]

    try:
        with open(shellcode_file, "rb") as f:
            shellcode = f.read()
    except FileNotFoundError:
        print(f"File not found: {shellcode_file}")
        exit(1)

    encrypted_shellcode = xor_encrypt(shellcode)
    encrypted_file = f"{shellcode_file}.enc"
    with open(encrypted_file, "wb") as f:
        f.write(encrypted_shellcode)

    print(f"Shellcode saved in {encrypted_file}")