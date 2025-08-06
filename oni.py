#by styx
#Tussi-lover
#Sientase libre de modificar a su gusto querido usser que pase por aqui!

import socket
import threading
import sys
import random
import time
import os
import base64
import hashlib
import socks
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

RESET   = "\033[0m"
RED     = "\033[31m"
BLOOD   = "\033[38;2;139;0;0m"
PURPLE  = "\033[35m"
DARK_PURPLE = "\033[38;2;75;0;130m"
CYAN    = "\033[36m"
GREY    = "\033[90m"
DARK_GREY = "\033[38;2;40;40;40m"
WHITE   = "\033[97m"
BOLD    = "\033[1m"
DEFAULT_PORT = 12345 ## Modifique usser
BUFFER_SIZE = 4096 ## Modifique usser
MAX_FILE_SIZE = 50 * 1024 * 1024 ## Modifique usser
TOR_PROXY_HOST = '127.0.0.1'
TOR_PROXY_PORT = 9050

def mostrar_banner():
    banner = f"""{BLOOD}
    ╔══════════════════════════════════════════════════════════════════╗
    ║  ████████╗ ██████╗ ██████╗      ██████╗██╗  ██╗ █████╗ ████████╗ ║
    ║  ╚══██╔══╝██╔═══██╗██╔══██╗    ██╔════╝██║  ██║██╔══██╗╚══██╔══╝ ║
    ║     ██║   ██║   ██║██████╔╝    ██║     ███████║███████║   ██║    ║
    ║     ██║   ██║   ██║██╔══██╗    ██║     ██╔══██║██╔══██║   ██║    ║
    ║     ██║   ╚██████╔╝██║  ██║    ╚██████╗██║  ██║██║  ██║   ██║    ║
    ║     ╚═╝    ╚═════╝ ╚═╝  ╚═╝     ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ║
    ║                                                                  ║
    ║                    By Styx - Rudy xxxxxx                         ║
    ║                     Mundo Tor Anxsb593                           ║
    ╚══════════════════════════════════════════════════════════════════╝

    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⠶⠶⠶⠶⢦⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡾⠛⠁⠀⠀⠀⠀⠀⠀⠈⠙⢷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡾⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡾⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⡀⠀⠀𝕲𝖗𝖊𝖊𝖉'𝖘⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀⠀⣀⣀⣀⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠸⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀⣠⡴⠞⠛⠉⠉⣩⣍⠉⠉⠛⠳⢦⣄⠀⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡀⠀⣴⡿⣧⣀⠀⢀⣠⡴⠋⠙⢷⣄⡀⠀⣀⣼⢿⣦⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣧⡾⠋⣷⠈⠉⠉⠉⠉⠀⠀⠀⠀⠉⠉⠋⠉⠁⣼⠙⢷⣼⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣇⠀⢻⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡟⠀⣸⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣹⣆⠀⢻⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡟⠀⣰⣏⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⠞⠋⠁⠙⢷⣄⠙⢷⣀⠀⠀⠀⠀⠀⠀⢀⡴⠋⢀⡾⠋⠈⠙⠻⢦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡾⠋⠀⠀⠀⠀⠀⠀⠹⢦⡀⠙⠳⠶⢤⡤⠶⠞⠋⢀⡴⠟⠀⠀⠀⠀⠀⠀⠙⠻⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣼⠋⠀⠀⢀⣤⣤⣤⣤⣤⣤⣤⣿⣦⣤⣤⣤⣤⣤⣤⣴⣿⣤⣤⣤⣤⣤⣤⣤⡀⠀⠀⠙⣧⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣸⠏⠀⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀⠀⢠⣴⠞⠛⠛⠻⢦⡄⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⠀⠀⠸⣇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢠⡟⠀⠀⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀⠀⣿⣿⢶⣄⣠⡶⣦⣿⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⠀⠀⠀⢻⡄⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣾⠁⠀⠀⠀⠀⠘⣇⠀⠀⠀⠀⠀⠀⠀⢻⣿⠶⠟⠻⠶⢿⡿⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⠀⠀⠀⠈⣿⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢰⡏⠀⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⢾⣄⣹⣦⣀⣀⣴⢟⣠⡶⠀⠀⠀⠀⠀⠀⣼⠀⠀⠀⠀⠀⠀⢸⡇⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠈⠛⠿⣭⣭⡿⠛⠁⠀⠀⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⠘⣧⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀⢿⡀⠀⠀⠀⠀⠀⠀⣀⡴⠞⠋⠙⠳⢦⣀⠀⠀⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⢰⡏⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠈⢿⣄⣀⠀⠀⢀⣤⣼⣧⣤⣤⣤⣤⣤⣿⣭⣤⣤⣤⣤⣤⣤⣭⣿⣤⣤⣤⣤⣤⣼⣿⣤⣄⠀⠀⣀⣠⡾⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠈⠉⠛⠛⠻⢧⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠤⠼⠟⠛⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    {RESET}"""
    print(banner)
def mostrar_menu():
    print(f"{RED}                   𝐖𝐄𝐋𝐂𝐎𝐌𝐄             {RESET}")
    print(f"""{DARK_PURPLE}
    ┌─────────────────────────────────────┐
    │             MENU PRINCIPAL          │
    ├─────────────────────────────────────┤
    │ [1] Crear Servidor                  │
    │ [2] Conectar a Servidor             │
    │ [3] Configurar Tor                  │
    │ [4] Salir                           │
    └─────────────────────────────────────┘
    {RESET}""")
def verificar_tor():
    try:
        socks.set_default_proxy(socks.SOCKS5, TOR_PROXY_HOST, TOR_PROXY_PORT)
        test_socket = socks.socksocket()
        test_socket.settimeout(5)
        test_socket.connect(("check.torproject.org", 80))
        test_socket.close()
        return True
    except:
        return False
class SecureChat:
    def __init__(self):
        self.clients = {}
        self.server_socket = None
        self.running = False
        self.cipher = None
    def derive_key(self, password, salt=None):
        if salt is None:
            salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt
    def encrypt_message(self, message, cipher):
        return cipher.encrypt(message.encode())
    def decrypt_message(self, encrypted_message, cipher):
        return cipher.decrypt(encrypted_message).decode()
    def broadcast_message(self, message, sender_socket=None):
        disconnected = []
        for client_socket, client_info in self.clients.items():
            if client_socket != sender_socket:
                try:
                    encrypted_msg = self.encrypt_message(message, client_info['cipher'])
                    client_socket.send(len(encrypted_msg).to_bytes(4, 'big'))
                    client_socket.send(encrypted_msg)
                except:
                    disconnected.append(client_socket)
        for client_socket in disconnected:
            self.disconnect_client(client_socket)
    def disconnect_client(self, client_socket):
        if client_socket in self.clients:
            nick = self.clients[client_socket]['nick']
            del self.clients[client_socket]
            self.broadcast_message(f"[SISTEMA] {nick} ha salido del chat")
            try:
                client_socket.close()
            except:
                pass
    def handle_client(self, client_socket, addr):
        try:
            client_socket.send(b"AUTH_REQUEST")
            
            auth_data = client_socket.recv(1024)
            try:
                password = auth_data.decode().strip()
            except:
                client_socket.close()
                return
            
            test_key, salt = self.derive_key(password)
            client_socket.send(salt)

            self.cipher = Fernet(test_key)

            nick_data = client_socket.recv(1024)
            nick = nick_data.decode().strip()

            self.clients[client_socket] = {
                'nick': nick,
                'addr': addr,
                'cipher': Fernet(test_key)
            }
            self.broadcast_message(f"{BLOOD}[SISTEMA] {nick} se ha unido al chat!{RESET}")
            while self.running:
                try:
                    msg_len_data = client_socket.recv(4)
                    if not msg_len_data:
                        break
                    msg_len = int.from_bytes(msg_len_data, 'big')
                    if msg_len > BUFFER_SIZE:
                        break
                    encrypted_msg = client_socket.recv(msg_len)
                    if not encrypted_msg:
                        break
                    cipher = self.clients[client_socket]['cipher']
                    message = self.decrypt_message(encrypted_msg, cipher)
                    if message.startswith("FILE:"):
                        self.handle_file_transfer(message, client_socket)
                    else:
                        formatted_msg = f"{nick}: {message}"
                        self.broadcast_message(formatted_msg, client_socket)
                except Exception as e:
                    break
        except Exception as e:
            pass
        finally:
            self.disconnect_client(client_socket)
    def handle_file_transfer(self, file_header, sender_socket):
        try:
            parts = file_header.split(":")
            filename = parts[1]
            filesize = int(parts[2])
            if filesize > MAX_FILE_SIZE:
                return
            sender_nick = self.clients[sender_socket]['nick']
            self.broadcast_message(f"[ARCHIVO] {sender_nick} esta enviando: {filename} ({filesize} bytes)")
            file_data = b""
            remaining = filesize
            while remaining > 0:
                chunk = sender_socket.recv(min(remaining, BUFFER_SIZE))
                if not chunk:
                    break
                file_data += chunk
                remaining -= len(chunk)
            for client_socket, client_info in self.clients.items():
                if client_socket != sender_socket:
                    try:
                        file_msg = f"FILE_INCOMING:{filename}:{filesize}"
                        encrypted_msg = self.encrypt_message(file_msg, client_info['cipher'])
                        client_socket.send(len(encrypted_msg).to_bytes(4, 'big'))
                        client_socket.send(encrypted_msg)
                        client_socket.send(file_data)
                    except:
                        pass
        except Exception as e:
            pass
    def start_server(self, port, password):
        key, salt = self.derive_key(password)
        self.cipher = Fernet(key)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.server_socket.bind(('0.0.0.0', port))
            self.server_socket.listen(10)
            self.running = True
            print(f"""{DARK_PURPLE}
                  ┌─────────────────────────────────────┐
                  │ SERVIDOR LISTO EN PUERTO {port:<8}  │
                  │ Esperando conexiones via TOR...     │
                  └─────────────────────────────────────┘
                  {RESET}""")
            while self.running:
                try:
                    client_socket, addr = self.server_socket.accept()
                    print(f"Nueva conexion desde: {addr[0]}")
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, addr),
                        daemon=True
                    )
                    client_thread.start()
                except:
                    break
        except Exception as e:
            print(f"Error del servidor: {e}")
        finally:
            self.cleanup()
    def cleanup(self):
        self.running = False
        for client_socket in list(self.clients.keys()):
            try:
                client_socket.close()
            except:
                pass
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
class ChatClient:
    def __init__(self):
        self.socket = None
        self.running = False
        self.cipher = None
    def derive_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    def encrypt_message(self, message):
        if self.cipher:
            return self.cipher.encrypt(message.encode())
        return message.encode()
    def decrypt_message(self, encrypted_message):
        if self.cipher:
            return self.cipher.decrypt(encrypted_message).decode()
        return encrypted_message.decode()
    def receive_messages(self):
        while self.running:
            try:
                msg_len_data = self.socket.recv(4)
                if not msg_len_data:
                    break
                msg_len = int.from_bytes(msg_len_data, 'big')
                encrypted_msg = self.socket.recv(msg_len)
                message = self.decrypt_message(encrypted_msg)
                if message.startswith("FILE_INCOMING:"):
                    self.handle_incoming_file(message)
                else:
                    print(f"\r{message}")
                    print("> ", end="", flush=True)
            except Exception as e:
                break
        print("\nConexion cerrada")
    def handle_incoming_file(self, file_header):
        try:
            parts = file_header.split(":")
            filename = parts[1]
            filesize = int(parts[2])
            print(f"\nRecibiendo archivo!: {filename}")
            file_data = b""
            remaining = filesize
            while remaining > 0:
                chunk = self.socket.recv(min(remaining, BUFFER_SIZE))
                if not chunk:
                    break
                file_data += chunk
                remaining -= len(chunk)
            downloads_dir = "downloads"
            if not os.path.exists(downloads_dir):
                os.makedirs(downloads_dir)
            filepath = os.path.join(downloads_dir, filename)
            counter = 1
            base_name, extension = os.path.splitext(filename)
            while os.path.exists(filepath):
                new_filename = f"{base_name}_{counter}{extension}"
                filepath = os.path.join(downloads_dir, new_filename)
                counter += 1
            with open(filepath, 'wb') as f:
                f.write(file_data)
            print(f"Archivo guardado!: {filepath}")
            print("> ", end="", flush=True)
        except Exception as e:
            print(f"Error recibiendo archivo :c {e}")
    def send_file(self, filepath):
        try:
            if not os.path.exists(filepath):
                print("Archivo no encontrado!")
                return
            filesize = os.path.getsize(filepath)
            if filesize > MAX_FILE_SIZE:
                print("Archivo demasiado grande!")
                return
            filename = os.path.basename(filepath)
            file_header = f"FILE:{filename}:{filesize}"
            encrypted_header = self.encrypt_message(file_header)
            self.socket.send(len(encrypted_header).to_bytes(4, 'big'))
            self.socket.send(encrypted_header)
            with open(filepath, 'rb') as f:
                while True:
                    chunk = f.read(BUFFER_SIZE)
                    if not chunk:
                        break
                    self.socket.send(chunk)
            print(f"Archivo enviado!: {filename}")
        except Exception as e:
            print(f"Error enviando archivo :c {e}")
    def connect(self, onion_address, port, password, nick):
        try:
            socks.set_default_proxy(socks.SOCKS5, TOR_PROXY_HOST, TOR_PROXY_PORT)
            self.socket = socks.socksocket()
            self.socket.settimeout(None)
            print(f"Conectando via TOR a {onion_address}:{port}...")
            self.socket.connect((onion_address, port))
            auth_request = self.socket.recv(1024)
            if auth_request != b"AUTH_REQUEST":
                print("Error de autenticacion!")
                return
            self.socket.send(password.encode())
            salt = self.socket.recv(16)
            key = self.derive_key(password, salt)
            self.cipher = Fernet(key)
            self.socket.send(nick.encode())
            self.running = True
            receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
            receive_thread.start()
            print(f"{BLOOD}CONECTADO COMO: {nick:<20}{RESET}")
            print(f"{RED}Servidor: {onion_address[:20]:<20}{RESET}")
            print(f"""{DARK_PURPLE}Comandos: /file <ruta>
                                             /exit
                                             /creator
                                            {RESET}""")
            while self.running:
                try:
                    message = input("> ")
                    if message.lower() in ['/exit', 'exit']:
                        break
                    elif message.startswith('/file '):
                        filepath = message[6:].strip()
                        self.send_file(filepath)
                    elif message.strip() == '/creator':
                        print(f"""{BLOOD}
                        Github: https://github.com/slyxicpy
                        Tg: https://t.me/slyxbys
                        {RESET}""")
                    else:
                        encrypted_msg = self.encrypt_message(message)
                        self.socket.send(len(encrypted_msg).to_bytes(4, 'big'))
                        self.socket.send(encrypted_msg)
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    print(f"Error :c {e}")
                    break
        except Exception as e:
            print(f"Error de conexion :c {e}")
        finally:
            self.cleanup()
    def cleanup(self):
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
def obtener_entrada(prompt, ocultar=False):
    if ocultar:
        import getpass
        return getpass.getpass(f"    {prompt}: ")
    else:
        return input(f"    {prompt}: ").strip()
def crear_servidor():
    print(f"""{PURPLE}
    ┌─────────────────────────────────────┐
    │         CREAR SERVIDOR              │
    └─────────────────────────────────────┘
    {RESET}""")
    puerto = obtener_entrada("Puerto: ")
    if not puerto:
        puerto = DEFAULT_PORT
    else:
        puerto = int(puerto)
    password = obtener_entrada("Contraseña del servidor", True)
    if not password:
        print("Contraseña requerida puta!")
        return
    server = SecureChat()
    try:
        server.start_server(puerto, password)
    except KeyboardInterrupt:
        print("\nCerrando servidor...")
        server.cleanup()
def conectar_cliente():
    print(f"""{PURPLE}
    ┌─────────────────────────────────────┐
    │       CONECTAR A SERVIDOR           │
    └─────────────────────────────────────┘
    {RESET}""")
    if not verificar_tor():
        print("TOR no esta funcionando")
        print("Verifica que TOR este ejecutandose!") #127.0.0.1:9050 o Su config bitch
        return
    print("TOR detectado correctamente!")
    onion_address = obtener_entrada("Direccion .onion:")
    if not onion_address:
        print("Direccion requerida!")
        return
    puerto = obtener_entrada("Puerto: ")
    if not puerto:
        puerto = DEFAULT_PORT
    else:
        puerto = int(puerto)
    nick = obtener_entrada("Tu nick: ")
    if not nick:
        nick = f"anon{random.randint(1000, 9999)}"
    password = obtener_entrada("Contraseña del servidor: ", True)
    if not password:
        print("Contraseña requerida!")
        return
    client = ChatClient()
    try:
        client.connect(onion_address, puerto, password, nick)
    except KeyboardInterrupt:
        print("\nDesconectando...")
        client.cleanup()
def configurar_tor():
    print(f"""{PURPLE}
               ┌─────────────────────────────────────┐
               │     Config requerida Tor  By styx   │
               └─────────────────────────────────────┘
    
    Para usar este chat necesitas TOR Browser o Tor daemon!
    Ejecuta TOR Browser: sudo systemctl start tor
    TOR estara On en 127.0.0.1:9050
    Si quieres crear un server:
    Edita el archivo torrc: sudo nano /etc/tor/torrc
    Agrega: HiddenServiceDir /var/lib/tor/chat/
            HiddenServicePort 12345 127.0.0.1:12345
    Reinicia TOR: sudo systemctl restart tor
    Tu direccion .onion estara en hostname! Suerte Usser!
    
    Presiona Enter para continuar!    
{RESET}""")
def main():
    while True:
        os.system('clear' if os.name == 'posix' else 'cls')
        mostrar_banner()
        mostrar_menu()
        try:
            opcion = input("\nSelecciona una opcion: ").strip()
            if opcion == '1':
                crear_servidor()
            elif opcion == '2':
                conectar_cliente()
            elif opcion == '3':
                configurar_tor()
            elif opcion == '4':
                print("\nSaliendo del programa Good bye!...")
                break
            else:
                print("Opcion invalida >;v")
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n\nSaliendo del programa Good Bye!...")
            break
        except Exception as e:
            print(f"Error: {e}")
            time.sleep(2)
if __name__ == "__main__":
    main()