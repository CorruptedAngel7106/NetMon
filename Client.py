'''NetMon Client For Version 1.0'''

import socket
import colorama

Host = '0.tcp.ngrok.io'
Port = 12140

__version__ = '1.0'

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((Host, Port))
    print(f"{colorama.Fore.GREEN}Connected to {Host}:{Port}{colorama.Fore.RESET}")
    while True:
        data = s.recv(1024).decode()
        s.send(__version__.encode('utf-8'))
        if data == '!disconnect':
            break
        if data:
            print(data)
            break
        else:
            print(f"{colorama.Fore.GREEN}System Up To Date!{colorama.Style.RESET_ALL}")
        data = s.recv(1024)
        print(data.decode('utf-8'))