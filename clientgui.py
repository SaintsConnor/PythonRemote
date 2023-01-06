
import sys
import sqlite3
import hashlib
import base64
import getpass
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QComboBox, QPushButton, QVBoxLayout, QGridLayout, QTabWidget, QTableWidget, QTableWidgetItem, QMessageBox
from PyQt5.QtGui import QIntValidator

class ServerManager(QWidget):
    def __init__(self):
        super().__init__()

        # Connect to the database
        self.conn = sqlite3.connect('servers.db')
        self.cursor = self.conn.cursor()

        # Create the servers table if it doesn't exist
        self.cursor.execute(
            '''CREATE TABLE IF NOT EXISTS servers (
                nickname text PRIMARY KEY,
                address text NOT NULL,
                port integer NOT NULL
            )'''
        )

        # Create the users table if it doesn't exist
        self.cursor.execute(
            '''CREATE TABLE IF NOT EXISTS users (
                username text PRIMARY KEY,
                password text NOT NULL
            )'''
        )

        # Create the permissions table if it doesn't exist
        self.cursor.execute(
            '''CREATE TABLE IF NOT EXISTS permissions (
                username text NOT NULL,
                nickname text NOT NULL,
                FOREIGN KEY (username) REFERENCES users(username),
                FOREIGN KEY (nickname) REFERENCES servers(nickname),
                PRIMARY KEY (username, nickname)
            )'''
        )

        # Create a socket
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Set up the GUI
        self.initUI()

    def initUI(self):
        # Create widgets
        self.serverLabel = QLabel('Server:')
        self.serverComboBox = QComboBox(self)
        self.usernameLabel = QLabel('Username:')
        self.usernameLineEdit = QLineEdit(self)
        self.passwordLabel = QLabel('Password:')
        
    def connect(self):
        # Get the server and login information
        nickname = self.serverComboBox.currentText()
        username = self.usernameLineEdit.text()
        password = self.passwordLineEdit.text()

        # Check if the user has permission to access the server
        self.cursor.execute('SELECT * FROM permissions WHERE username=? AND nickname=?', (username, nickname))
        if not self.cursor.fetchone():
            QMessageBox.warning(self, 'Error', 'You do not have permission to access this server.')
            return

        # Encrypt the password
        encrypted_password = encrypt_password(password)

        # Update the password in the database
        self.cursor.execute('UPDATE users SET password=? WHERE username=?', (encrypted_password, username))
        self.conn.commit()

        # Connect to the server
        self.cursor.execute('SELECT * FROM servers WHERE nickname=?', (nickname,))
        address, port = self.cursor.fetchone()[1:]
        self.s.connect((address, port))
        self.s.sendall((username + ' ' + password).encode())
        response = self.s.recv(1024).decode()
        if response == 'Authentication successful':
            QMessageBox.information(self, 'Success', 'Connected to the server.')
        else:
            QMessageBox.warning(self, 'Error', 'Authentication failed.')

    def changePassword(self):
        # Get the username and new password
        username = self.changePasswordUsernameLineEdit.text()
        password = self.changePasswordPasswordLineEdit.text()

        # Encrypt the password
        encrypted_password = self.encrypt_password(password)

        # Update the password in the database
        self.cursor.execute('UPDATE users SET password=? WHERE username=?', (encrypted_password, username))
        self.conn.commit()
        QMessageBox.information(self, 'Success', 'Password changed successfully.')
        
def deleteUser(self):
        # Get the username
        username = self.deleteUserUsernameLineEdit.text()

        # Delete the user from the database
        self.cursor.execute('DELETE FROM users WHERE username=?', (username,))
        self.conn.commit()
        QMessageBox.information(self, 'Success', 'User deleted successfully.')

    def grantAccess(self):
        # Get the username and server
        username = self.grantAccessUsernameLineEdit.text()
        nickname = self.grantAccessServerComboBox.currentText()

        # Grant access to the server
        self.cursor.execute('INSERT INTO permissions VALUES (?, ?)', (username, nickname))
        self.conn.commit()
        QMessageBox.information(self, 'Success', 'Access granted successfully.')

    def revokeAccess(self):
        # Get the username and server
        username = self.revokeAccessUsernameLineEdit.text()
        nickname = self.revokeAccessServerComboBox.currentText()

        # Revoke access to the server
        self.cursor.execute('DELETE FROM permissions WHERE username=? AND nickname=?', (username, nickname))
        self.conn.commit()
        QMessageBox.information(self, 'Success', 'Access revoked successfully.')
        
    def addServer(self):
        # Get the server information
        nickname = self.addServerNicknameLineEdit.text()
        address = self.addServerAddressLineEdit.text()
        port = self.addServerPortLineEdit.text()

        # Add the server to the database
        self.cursor.execute('INSERT INTO servers VALUES (?, ?, ?)', (nickname, address, port))
        self.conn.commit()
        QMessageBox.information(self, 'Success', 'Server added successfully.')
    def deleteServer(self):
        # Get the server
        nickname = self.deleteServerComboBox.currentText()

        # Delete the server from the database
        self.cursor.execute('DELETE FROM servers WHERE nickname=?', (nickname,))
        self.conn.commit()
        QMessageBox.information(self, 'Success', 'Server deleted successfully.')

    def encrypt_password(self, password):
        # Generate a random salt
        salt = get_random_bytes(8)

        # Hash the password with the salt
        hasher = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

        # Base64 encode the salt and hashed password
        salt_b64 = base64.b64encode(salt).decode()
        hashed_b64 = base64.b64encode(hasher).decode()

        # Concatenate the salt and hashed password and return them
        return salt_b64 + '$' + hashed_b64

    def verify_password(self, password, password_hash):
        # Split the salt and hashed password
        salt, hashed = password_hash.split('$')

        # Base64 decode the salt and hashed password
        salt_b = base64.b64decode(salt)
        hashed_b = base64.b64decode(hashed)

        # Hash the password with the salt
        hasher = hashlib.pbkdf2_hmac('sha256', password.encode(), salt_b, 100000)

        # Compare the hashed password to the stored hashed password
        return hashed_b == hasher

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = ServerManager()
    sys.exit(app.exec_())
