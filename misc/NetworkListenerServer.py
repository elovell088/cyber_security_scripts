#Security projects - Network Listener - Written by: Eric Lovell
import socket

HOST = ''  # Host IP or hostname
PORT = 443  # Port to listen on

#Create a socket object
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
    
    server_socket.bind((HOST, PORT))
    server_socket.listen()

    print(f"Listening on {HOST}:{PORT}")
  
    client_socket, client_address = server_socket.accept()
    print(f"Connected to {client_address[0]}:{client_address[1]}")

    while True:
        data = client_socket.recv(1024)
        if not data:
            break
        received_data = data.decode('utf-8')
        print(f"Received data: {received_data}")
        
        #Input code here to do something with the received data#
        
    #Close connection
    client_socket.close()
