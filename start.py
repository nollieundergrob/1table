import threading
import os
import socket

# ip = '0.0.0.0'
# ip = 'localhost'
ip = socket.gethostbyname(socket.gethostname())
port = 25565
verbosity = 3

def start_api():
    os.system(f'daphne -p {port} -b {ip} -v {verbosity} -s NOLLIEUNDERGROB config.asgi:application')

start_api()