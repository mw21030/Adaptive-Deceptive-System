import docker
import time
import socket
import ssl

HOST = '192.168.220.129'         # Listen on all network interfaces
PORT = 8443             # Must match REMOTE_PORT in your sender script
SERVER_CERT = '/home/mw/server.pem'
SERVER_KEY = '/home/mw/server.key'
CA_CERT = '/home/mw/ca.pem'

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile=SERVER_CERT, keyfile=SERVER_KEY)
context.load_verify_locations(cafile=CA_CERT)
context.verify_mode = ssl.CERT_REQUIRED

with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    sock.bind((HOST, PORT))
    sock.listen(5)
    print(f"Server listening on {HOST}:{PORT}")

    # Wrap the socket in an SSL context (server_side=True)
    with context.wrap_socket(sock, server_side=True) as ssock:
        while True:
            try:
                # Accept a connection
                conn, addr = ssock.accept()
                print(f"Connection from {addr}")
                
                # Read data from the client
                data = conn.recv(4096)
                if data:
                    print("Received alert:", data.decode())
                
                # Close the connection
                conn.close()
            except Exception as e:
                print("Error:", e)

def main():
    print ("[+] Starting orchestrator...")
if __name__ == "__main__":
    main()
