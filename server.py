import socket

class Server:
    def __init__(self):
        # Create a TCP/IP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Bind the socket to the port
        server_address = ('localhost', 10000)
        print('Starting up on {} port {}'.format(*server_address))
        self.sock.bind(server_address)

        # Listen for incoming connections
        self.sock.listen(1)

    def run(self):
        while True:
            # Wait for a connection
            print('Waiting for a connection...')
            connection, client_address = self.sock.accept()
            try:
                # Receive the username
                username = connection.recv(1024).decode()

                # Send the password prompt
                connection.send('Enter your password: '.encode())

                # Receive the password
                password = connection.recv(1024).decode()

                # Check the password
                if self.verify_password(password):
                    # Grant access
                    connection.send('Access granted.'.encode())

                    # Receive commands and execute them
                    while True:
                        command = connection.recv(1024).decode()
                        if command == 'exit':
                            break
                        result = self.execute_command(command)
                        connection.send(result.encode())
                else:
                    # Deny access
                    connection.send('Access denied.'.encode())

            finally:
                # Clean up the connection
                connection.close()

server = Server()
server.run()
