
#!/usr/bin/env python3
import argparse
import os
import sys
from getpass import getpass

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes

MAGIC = b"AESC"
VERSION = 1
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
RESERVED_LEN = 3  # reservado para uso futuro
HEADER_LEN = len(MAGIC) + 1 + SALT_LEN + NONCE_LEN + RESERVED_LEN
CHUNK_SIZE = 64 * 1024  # 64 KiB

def derive_key(password: bytes, salt: bytes) -> bytes:
    # Parámetros para desktop; Ajustar N/r/p para dispositivos más lentos/rápidos.
    return scrypt(password, salt, key_len=32, N=2**14, r=8, p=1)

def encrypt_file(in_path: str, out_path: str) -> None:
    if not os.path.isfile(in_path):
        raise FileNotFoundError(f"Input file not found: {in_path}")

    if os.path.exists(out_path):
        raise FileExistsError(f"Refusing to overwrite existing file: {out_path}")

    password = getpass("Enter password to encrypt: ").encode("utf-8")
    if not password:
        raise ValueError("Empty passwords are not allowed.")

    salt = get_random_bytes(SALT_LEN)
    key = derive_key(password, salt)
    nonce = get_random_bytes(NONCE_LEN)

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_LEN)

    with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
        # Escribir encabezado (header)
        fout.write(MAGIC)
        fout.write(bytes([VERSION]))
        fout.write(salt)
        fout.write(nonce)
        fout.write(b"\x00" * RESERVED_LEN)

        # cifrar stream y escribir en bloques
        while True:
            chunk = fin.read(CHUNK_SIZE)
            if not chunk:
                break
            enc = cipher.encrypt(chunk)
            fout.write(enc)

        # Finalizar y escribir tag al final del archivo
        tag = cipher.digest()
        fout.write(tag)

    # cleanup de memoria por si acaso
    del password, key

def decrypt_file(in_path: str, out_path: str) -> None:
    if not os.path.isfile(in_path):
        raise FileNotFoundError(f"Input file not found: {in_path}")

    if os.path.exists(out_path):
        raise FileExistsError(f"Refusing to overwrite existing file: {out_path}")

    password = getpass("Enter password to decrypt: ").encode("utf-8")
    if not password:
        raise ValueError("Empty passwords are not allowed.")

    file_size = os.path.getsize(in_path)
    if file_size < HEADER_LEN + TAG_LEN:
        raise ValueError("File too small to be a valid AESC container.")

    with open(in_path, "rb") as fin:
        # lee y valida el encabezado (header)
        magic = fin.read(len(MAGIC))
        if magic != MAGIC:
            raise ValueError("Invalid file header (magic mismatch).")
        ver = fin.read(1)
        if not ver or ver[0] != VERSION:
            raise ValueError(f"Incompatible version: {ver[0] if ver else 'None'}")
        salt = fin.read(SALT_LEN)
        if len(salt) != SALT_LEN:
            raise ValueError("Corrupted header: salt length mismatch.")
        nonce = fin.read(NONCE_LEN)
        if len(nonce) != NONCE_LEN:
            raise ValueError("Corrupted header: nonce length mismatch.")
        _reserved = fin.read(RESERVED_LEN)  # actualmente no utilizado

        key = derive_key(password, salt)

        # Determinar longitud del texto cifrado (total - encabezado - tag)
        ct_len = file_size - HEADER_LEN - TAG_LEN
        if ct_len < 0:
            raise ValueError("Corrupted file: negative ciphertext length.")

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_LEN)

        # Descifrar stream: leer exactamente ct_len bytes como texto cifrado
        remaining = ct_len
        with open(out_path, "wb") as fout:
            while remaining > 0:
                to_read = CHUNK_SIZE if remaining >= CHUNK_SIZE else remaining
                chunk = fin.read(to_read)
                if not chunk:
                    raise ValueError("Unexpected EOF while reading ciphertext.")
                remaining -= len(chunk)
                dec = cipher.decrypt(chunk)
                fout.write(dec)

            # leer y verificar el tag al final del archivo
            tag = fin.read(TAG_LEN)
            if len(tag) != TAG_LEN:
                raise ValueError("Corrupted file: tag length mismatch.")

            try:
                cipher.verify(tag)
            except ValueError:
                # Autenticacion fallida: eliminar salida parcial por seguridad.
                fout.close()
                try:
                    os.remove(out_path)
                except OSError:
                    pass
                raise ValueError("Authentication failed: wrong password or corrupted file.")

    # cleanup de memoria por si acaso
    del password, key

def main():
    # crear el parser de argumentos de línea de comandos
    # el formato es: python aesc.py <encrypt|decrypt> --in <input> --out <output>
    
    parser = argparse.ArgumentParser(
        description="AES-GCM file encryptor/decryptor using PyCryptodome with scrypt KDF."
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_enc = sub.add_parser("encrypt", help="Encrypt a file")
    p_enc.add_argument("--in", dest="in_path", required=True, help="Input file path")
    p_enc.add_argument("--out", dest="out_path", required=True, help="Output file path")

    p_dec = sub.add_parser("decrypt", help="Decrypt a file")
    p_dec.add_argument("--in", dest="in_path", required=True, help="Encrypted file path (.aes)")
    p_dec.add_argument("--out", dest="out_path", required=True, help="Decrypted output path")

    args = parser.parse_args()

    try:
        if args.cmd == "encrypt":
            encrypt_file(args.in_path, args.out_path)
            print(f"✅ Encrypted: {args.in_path} -> {args.out_path}")
        elif args.cmd == "decrypt":
            decrypt_file(args.in_path, args.out_path)
            print(f"✅ Decrypted: {args.in_path} -> {args.out_path}")
        else:
            parser.error("Unknown command.")
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
