import socket

# Dictionary of available servers
servers = {}

# Create a socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def add_server(nickname, address, port):
    # Add the server to the dictionary
    servers[nickname] = (address, port)
    print(f'Added server "{nickname}"')

def delete_server(nickname):
    # Delete the server from the dictionary
    del servers[nickname]
    print(f'Deleted server "{nickname}"')

while True:
    # Display menu
    print('Select an option:')
    print('1: List servers')
    print('2: Connect to a server')
    print('3: Add a server')
    print('4: Delete a server')
    print('0: Exit')
    selection = int(input())

    # List available servers
    if selection == 1:
        for nickname, server in servers.items():
            print(f'{nickname}: {server[0]}:{server[1]}')

    # Connect to a server
    elif selection == 2:
        # Display a list of available servers
        print('Select a server:')
        for i, nickname in enumerate(servers):
            print(f'{i + 1}: {nickname}')

        # Prompt the user to select a server
        selection = int(input())

        # Connect to the selected server
        s.connect(servers[list(servers.keys())[selection - 1]])

        # Send commands to the server until the user wants to disconnect
        while True:
            command = input('Enter a command: ')
            if command == 'disconnect':
                break
            s.sendall(command.encode())
            response = s.recv(1024).decode()
            print(response)

        # Close the connection
        s.close()

    # Add a server
    elif selection == 3:
        nickname = input('Enter a nickname for the server: ')
        address = input('Enter the IP address of the server: ')
        port = int(input('Enter the port number of the server: '))
        add_server(nickname, address, port)

    # Delete a server
    elif selection == 4:
        # Display a list of available servers
        print('Select a server to delete:')
        for i, nickname in enumerate(servers):
            print(f'{i + 1}: {nickname}')

        # Prompt the user to select a server
        selection = int(input())
        delete_server(list(servers.keys())[selection - 1])

    # If the user selects "Exit", exit the program
    else:
        break
