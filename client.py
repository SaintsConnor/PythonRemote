import getpass
import sqlite3
import socket
import hashlib
import base64
import os

from Crypto import Random
from Crypto.Cipher import AES

class Server:
    def __init__(self):
        self.s = socket.socket()
        self.conn = sqlite3.connect('servers.db')
        self.cursor = self.conn.cursor()
        self.cursor.execute(
            '''CREATE TABLE IF NOT EXISTS servers (
            nickname TEXT,
            address TEXT,
            port INTEGER
            )'''
        )
        self.cursor.execute(
            '''CREATE TABLE IF NOT EXISTS permissions (
            username TEXT,
            nickname TEXT
            )'''
        )
        self.cursor.execute(
            '''CREATE TABLE IF NOT EXISTS admins (
            username TEXT,
            password TEXT
            )'''
        )
        self.cursor.execute(
            '''CREATE TABLE IF NOT EXISTS users (
            username TEXT,
            password TEXT
            )'''
        )
        self.conn.commit()

    def encrypt_password(self, password):
        # Generate a salt
        salt = os.urandom(16)

        # Hash the password
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

        # Encrypt the password hash
        key = b'\x8c\x9e\x9d\x0b\x0e\xaa\xbeF\x92\x8f\xe6\x9a\x0b\x16\x9aG\x0e'
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CFB, iv)
        encrypted_password = iv + cipher.encrypt(password_hash)

        # Encode the encrypted password as base64
        encoded_password = base64.b64encode(encrypted_password)

        return encoded_password

    def verify_password(self, password, password_hash):
        # Decode the password hash from base64
        decoded_password = base64.b64decode(password_hash)

        # Decrypt the password hash
        key = b'\x8c\x9e\x9d\x0b\x0e\xaa\xbeF\x92\x8f\xe6\x9a\x0b\x16\x9aG\x0e'
        iv = decoded_password[:16]
        cipher = AES.new(key, AES.MODE_CFB, iv)
        decrypted_password = cipher.decrypt(decoded_password[16:])

        # Hash the password
        salt = decrypted_password[:16]
        password_hash_check = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

        # Compare the hashes
        if password_hash_check == decrypted_password:
            return True
        else:
            return False
    def login(self):
        # Get the username and password
        username = input("Enter your username: ")
        password = getpass.getpass("Enter your password: ")

        # Check if the user is an admin
        self.cursor.execute('SELECT * FROM admins WHERE username=?', (username,))
        user = self.cursor.fetchone()
        if user:
            # Check if the password is correct
            if self.verify_password(password, user[1]):
                print("Logged in as an admin.")
                self.admin_menu()
                return
            else:
                print("Error: Incorrect password.")
                return

        # Check if the user is a regular user
        self.cursor.execute('SELECT * FROM users WHERE username=?', (username,))
        user = self.cursor.fetchone()
        if user:
            # Check if the password is correct
            if self.verify_password(password, user[1]):
                print("Logged in as a user.")
                self.user_menu()
                return
            else:
                print("Error: Incorrect password.")
                return

        # If the user is neither an admin nor a regular user
        print("Error: Invalid username.")
    def admin_menu(self):
        while True:
            # Display the menu
            print("1. Add a server")
            print("2. Delete a server")
            print("3. Grant access to a user")
            print("4. Revoke access from a user")
            print("5. Add an admin")
            print("6. Change your password")
            print("7. Log out")

            # Get the user's choice
            choice = input("Enter your choice: ")
    
            # Process the choice
            if choice == '1':
                self.add_server()
            elif choice == '2':
                self.delete_server()
            elif choice == '3':
                self.grant_access()
            elif choice == '4':
                self.revoke_access()
            elif choice == '5':
                self.add_admin()
            elif choice == '6':
                self.change_password()
            elif choice == '7':
                return

    def user_menu(self):
        while True:
            # Display the menu
            print("1. Connect to a server")
            print("2. Change your password")
            print("3. Log out")

            # Get the user's choice
            choice = input("Enter your choice: ")

            # Process the choice
            if choice == '1':
                self.connect()
            elif choice == '2':
                self.change_password()
            elif choice == '3':
                return

    def main(self):
        while True:
            # Display the menu
            print("1. Login")
            print("2. Connect to a server")
            print("3. Quit")
    
            # Get the user's choice
            choice = input("Enter your choice: ")
    
            # Process the choice
            if choice == '1':
                self.login()
            elif choice == '2':
                self.connect()
            elif choice == '3':
                return
    def add_server(self):
        # Get the server's nickname, address, and port
        nickname = input("Enter the server's nickname: ")
        address = input("Enter the server's address: ")
        port = input("Enter the server's port: ")
    
        # Add the server to the database
        self.cursor.execute('INSERT INTO servers VALUES (?, ?, ?)', (nickname, address, port))
        self.conn.commit()
    
    def delete_server(self):
        # Get the server's nickname
        nickname = input("Enter the server's nickname: ")
    
        # Delete the server from the database
        self.cursor.execute('DELETE FROM servers WHERE nickname=?', (nickname,))
        self.conn.commit()
    
    def grant_access(self):
        # Get the username and server nickname
        username = input("Enter the user's username: ")
        nickname = input("Enter the server's nickname: ")
    
        # Grant the user access to the server
        self.cursor.execute('INSERT INTO permissions VALUES (?, ?)', (username, nickname))
        self.conn.commit()
    
    def revoke_access(self):
        # Get the username and server nickname
        username = input("Enter the user's username: ")
        nickname = input("Enter the server's nickname: ")
    
        # Revoke the user's access to the server
        self.cursor.execute('DELETE FROM permissions WHERE username=? AND nickname=?', (username, nickname))
        self.conn.commit()
    
    def add_admin(self):
        # Get the username and password
        username = input("Enter the admin's username: ")
        password = getpass.getpass("Enter the admin's password: ")
    
        # Encrypt the password
        encrypted_password = self.encrypt_password(password)
    
        # Add the admin to the database
        self.cursor.execute('INSERT INTO admins VALUES (?, ?)', (username, encrypted_password))
        self.conn.commit()
    
    def change_password(self):
        # Get the username and new password
        username = input("Enter your username: ")
        new_password = getpass.getpass("Enter your new password: ")
    
        # Encrypt the new password
        encrypted_new_password = self.encrypt_password(new_password)
    
        # Update the password in the database
        self.cursor.execute('UPDATE admins SET password=? WHERE username=?', (encrypted_new_password, username))
        self.conn.commit()
    def connect(self):
        # Get the server nickname
        nickname = input("Enter the server's nickname: ")
    
        # Get the user's permission to access the server
        self.cursor.execute('SELECT * FROM permissions WHERE username=? AND nickname=?', (self.username, nickname))
        permission = self.cursor.fetchone()
        if not permission:
            print("Error: You do not have permission to access this server.")
            return

        # Get the server's address and port
        self.cursor.execute('SELECT * FROM servers WHERE nickname=?', (nickname,))
        server = self.cursor.fetchone()
        address = server[1]
        port = server[2]

        # Connect to the server
        self.s.connect((address, port))

        # Send the username to the server
        self.s.send(self.username.encode())
    
        # Receive the password prompt from the server
        password_prompt = self.s.recv(1024).decode()
        print(password_prompt)
    
        # Send the password to the server
        self.s.send(self.password.encode())
    
        # Receive the response from the server
        response = self.s.recv(1024).decode()
        if response == 'Access granted.':
            print(response)
            self.s.send(' '.encode())
            while True:
                command = input("Enter a command: ")
                self.s.send(command.encode())
                if command == 'exit':
                    break
                result = self.s.recv(1024).decode()
                print(result)
            self.s.close()
        else:
            print(response)
            self.s.close()
client = Client()
client.main()

