import os
import sys
import subprocess
import base64
import secrets
import logging
from getpass import getpass
import argparse

# Instalação automática de módulos necessários
REQUIRED_MODULES = ["argon2-cffi", "cryptography", "click"]

def install_missing_modules():
    for module in REQUIRED_MODULES:
        try:
            __import__(module.replace("-", "_"))
        except ImportError:
            print(f"[!] Módulo '{module}' não encontrado. Instalando...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", module])

install_missing_modules()

# Importações após garantir dependências
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Setup de logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

# ====== Funções de segurança e criptografia ======

def secure_boot_check():
    logging.info("Verificando Secure Boot... [simulado]")
    return True

def tpm_attestation_check():
    logging.info("Verificando attestation do TPM... [simulado]")
    return True

def verify_physical_identity():
    logging.info("Verificando identidade física (CAC/PIV simulado)...")
    return True

def generate_code_signing_keys():
    logging.info("Gerando chave RSA para assinatura do código...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    public_key = private_key.public_key()
    return private_key, public_key

def sign_data(data: bytes, private_key):
    signature = private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return signature

def derive_key(password: str, salt: bytes) -> bytes:
    key = hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=4,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=Type.ID
    )
    return key

def encrypt_data(key: bytes, plaintext: bytes) -> dict:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return {"nonce": nonce, "ciphertext": ciphertext}

def save_to_file(filename, content):
    with open(filename, 'wb') as f:
        f.write(content)
    logging.info(f"Conteúdo salvo com sucesso em: {filename}")

# ====== CLI Interface ======

def secure_storage():
    if not (secure_boot_check() and tpm_attestation_check() and verify_physical_identity()):
        logging.error("Requisitos de ambiente seguro não atendidos.")
        return

    password = getpass("Digite sua senha segura: ")
    if len(password) < 12:
        logging.error("A senha deve ter no mínimo 12 caracteres.")
        return

    salt = os.urandom(16)
    pepper = secrets.token_bytes(32)
    key = derive_key(password + pepper.hex(), salt)

    try:
        data = input("Digite os dados sensíveis a proteger: ").encode()
    except KeyboardInterrupt:
        logging.warning("Operação cancelada pelo usuário.")
        return

    encrypted = encrypt_data(key, data)
    priv_key, pub_key = generate_code_signing_keys()
    signed = sign_data(encrypted["ciphertext"], priv_key)

    # Armazenar outputs em arquivos seguros
    save_to_file("dados_criptografados.bin", encrypted["ciphertext"])
    save_to_file("nonce.bin", encrypted["nonce"])
    save_to_file("assinatura.sig", signed)
    save_to_file("chave_publica.pem", pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

    logging.info("Dados criptografados e assinados com sucesso.")
    logging.info("Certifique-se de manter os arquivos gerados em local seguro.")

# ====== Ponto de entrada com argparse ======

def main():
    parser = argparse.ArgumentParser(description="Criptografia e Assinatura de Dados Sensíveis")
    parser.add_argument('--executar', action='store_true', help="Executa a proteção dos dados")
    args = parser.parse_args()

    if args.executar:
        secure_storage()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
