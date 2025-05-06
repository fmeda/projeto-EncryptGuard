import subprocess
import sys
from rich.console import Console
from rich.prompt import Prompt
from rich.progress import Progress
from rich.theme import Theme

# Definir tema personalizado
custom_theme = Theme({
    "info": "bold green",
    "warning": "bold yellow",
    "error": "bold red",
    "success": "bold blue",
    "title": "bold cyan"
})

# Inicializar console do rich
console = Console(theme=custom_theme)

# Lista de módulos necessários
required_modules = [
    "pycryptodome",   # Para criptografia AES
    "pywin32"         # Para integração com Windows (win32api, win32crypt, etc.)
]

def check_and_install(module):
    try:
        __import__(module)
        console.print(f"[info]+ Módulo '{module}' já está instalado.[/info]")
    except ImportError:
        console.print(f"[warning]! Módulo '{module}' não encontrado. Instalando...[/warning]")
        subprocess.check_call([sys.executable, "-m", "pip", "install", module])

# Verificar se os módulos necessários estão instalados
for module in required_modules:
    check_and_install(module)

# Agora, pode seguir com a execução normal do programa

import os
import ctypes
import base64
import getpass
import hashlib
import win32crypt
import win32security
import win32api
import win32con
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Caminho seguro para armazenamento local de dados criptografados
SECURE_PATH = os.path.join(os.environ['PROGRAMDATA'], 'EncryptGuard')
DATA_FILE = os.path.join(SECURE_PATH, 'cred.sec')

# Garantir que o diretório existe com ACLs seguras
def ensure_secure_dir():
    if not os.path.exists(SECURE_PATH):
        os.makedirs(SECURE_PATH)
    os.system(f"icacls {SECURE_PATH} /inheritance:r /grant:r SYSTEM:F Administrators:F")

# Criptografar usando AES e proteger com DPAPI (dupla camada)
def encrypt_data(password: str) -> bytes:
    salt = get_random_bytes(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(password.encode())
    blob = salt + cipher.nonce + tag + ciphertext
    protected_blob = win32crypt.CryptProtectData(blob, None, None, None, None, 0)
    return protected_blob

# Descriptografar e validar
def decrypt_data(protected_blob: bytes) -> str:
    decrypted_blob = win32crypt.CryptUnprotectData(protected_blob, None, None, None, 0)[1]
    salt = decrypted_blob[:16]
    nonce = decrypted_blob[16:32]
    tag = decrypted_blob[32:48]
    ciphertext = decrypted_blob[48:]
    password = Prompt.ask("Reinsira sua senha para validar: ", password=True)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

# Salvar dados criptografados
def save_encrypted(blob):
    with open(DATA_FILE, 'wb') as f:
        f.write(blob)

# Carregar dados criptografados
def load_encrypted():
    with open(DATA_FILE, 'rb') as f:
        return f.read()

# Validar se é admin
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# Executar comandos com as credenciais protegidas
def secure_exec():
    console.print("[info]Executando com credenciais protegidas...[/info]")
    os.system("whoami")
    os.system("net session")  # Apenas administradores vão conseguir

# Interface principal CLI
if __name__ == '__main__':
    ensure_secure_dir()

    if not is_admin():
        console.print("[error]Este script requer permissão de administrador. Execute como Admin.[/error]")
        sys.exit(1)

    # Menu Interativo
    console.print("[title]EncryptGuard - Sistema de Proteção de Credenciais[/title]", justify="center")
    console.print("[info]1. Criar nova credencial[/info]")
    console.print("[info]2. Validar credencial existente[/info]")
    choice = Prompt.ask("Escolha uma opção:", choices=["1", "2"], default="1")

    if choice == "1":
        console.print("[info]Criando nova credencial...[/info]")
        pwd = Prompt.ask("Digite sua senha ou credencial:", password=True)
        encrypted_blob = encrypt_data(pwd)
        save_encrypted(encrypted_blob)
        console.print("[success]Credencial criptografada e salva com sucesso![/success]")

    elif choice == "2":
        try:
            encrypted_blob = load_encrypted()
            cred = decrypt_data(encrypted_blob)
            console.print("[success]Credencial validada com sucesso![/success]")
            secure_exec()
        except Exception as e:
            console.print(f"[error]Falha na validação da credencial: {str(e)}[/error]")
