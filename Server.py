'''Socket Server for NetMon'''
import socket
from pyngrok import ngrok

host = '0.0.0.0'
port = 9999

url = ngrok.connect(port, "tcp")

with socket.socket(
    socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((host, port))
    print(f"Server is running on {host}:{port}")
    s.listen()
    print(f"Server is listening on {url}")

    conn, addr = s.accept()
    with conn:
        print(f"Connected by {addr}")
        while True:
            data = conn.recv(1024)
            if not data:
                conn.send('!disconnected'.encode('utf-8'))
                conn.close()
                break
            if data.decode() != 'v1.0':
                conn.send('Update available run "NetMon --upgrade -a8"'.encode('utf-8'))

            
            print(data.decode('utf-8'))