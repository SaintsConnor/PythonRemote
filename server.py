import socket
import subprocess

# Create a socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to a local address and port
port = input("Enter port desired for use (Reccomended over 9001. This will be required when connecting via the client): ") 
s.bind(('localhost', port))

# Start listening for incoming connections
s.listen()

while True:
    # Accept an incoming connection
    conn, addr = s.accept()

    # Receive data from the client
    data = conn.recv(1024).decode()

    # If the client sends the "disconnect" command, close the connection and go back to listening for incoming connections
    if data == 'disconnect':
        conn.close()
        continue

    # Execute the command received from the client
    output = subprocess.run(data, capture_output=True)

    # Send the output of the command back to the client
    conn.sendall(output.stdout)

# Close the connection
conn.close()

