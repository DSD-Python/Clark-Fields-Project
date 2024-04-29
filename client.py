from http.client import responses
import sys
import requests
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QLineEdit, QVBoxLayout, QLabel

from selenium import webdriver
from selenium.webdriver.common.keys import Keys
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key

SERVER_URL = "https://dsd-project-afbb3ca3afdb.herokuapp.com/"

def automated_login_and_wait(username, password, wait_time):
    #CHANGE THE PATH FOR NEXT LINE
    driver = webdriver.Firefox(executable_path='/Users/ryanclark/DSD Project/old_stuff/geckodriver')
    driver.get('https://login.bc.edu/nidp/idff/sso?id=19&sid=0&option=credential&sid=0&target=https%3A%2F%2Fservices.bc.edu%2Fcommoncore%2Fmyservices.do')
    time.sleep(1)

    driver.find_element_by_id('username').send_keys(username)
    driver.find_element_by_id('password').send_keys(password)
    driver.find_element_by_id('password').send_keys(Keys.RETURN)

    time.sleep(wait_time)
    driver.quit()


class HomeWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        user_a_button = QPushButton('Be User A', self)
        user_a_button.clicked.connect(self.beUserA)

        user_b_button = QPushButton('Be User B', self)
        user_b_button.clicked.connect(self.beUserB)

        self.email_input = QLineEdit(self)
        self.email_input.setPlaceholderText("Enter your email")

        layout = QVBoxLayout()
        layout.addWidget(self.email_input)
        layout.addWidget(user_a_button)
        layout.addWidget(user_b_button)

        self.setLayout(layout)
        self.setWindowTitle('Home')

    def beUserA(self):
        self.public_key, self.private_key = self.registerUser(0)
        self.user_a_window = UserAWindow(self.public_key,self.private_key)
        self.user_a_window.show()

    def beUserB(self):
        self.public_key, self.private_key = self.registerUser(1)
        self.user_b_window = UserBWindow(self.public_key,self.private_key)
        self.user_b_window.show()

    def registerUser(self, user):
        email = self.email_input.text()
        public_key, private_key = self.generate_key_pair()
        public_key_serialized = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        private_key_serialized = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,  
            encryption_algorithm=serialization.NoEncryption()  
        )
        if user == 1:
            response = requests.post(f"{SERVER_URL}/register_user", json={"email": email, "public_key": public_key_serialized.decode()})
        return public_key_serialized.decode(), private_key_serialized.decode()

    def generate_key_pair(self):
        private_key = rsa.generate_private_key(
            backend=default_backend(),
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        return public_key, private_key


class UserAWindow(QWidget):
    def __init__(self, public_key, private_key):
        super().__init__()
        self.public_key = public_key
        self.private_key = private_key
        self.initUI()

    def initUI(self):
        self.username_input = QLineEdit(self)
        self.username_input.setPlaceholderText("Username")

        self.password_input = QLineEdit(self)
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.Password) 

        self.generate_button = QPushButton('Generate Code', self)
        self.generate_button.clicked.connect(self.generateCode)

        self.code_label = QLabel(self)

        self.email_input = QLineEdit(self)
        self.email_input.setPlaceholderText("User B's Email")

        layout = QVBoxLayout()
        layout.addWidget(self.username_input)
        layout.addWidget(self.password_input)
        layout.addWidget(self.email_input)
        layout.addWidget(self.generate_button)
        layout.addWidget(self.code_label)

        self.setLayout(layout)
        self.setWindowTitle('User A Window')

    def generateCode(self):
        username = self.username_input.text()
        password = self.password_input.text()
        email = self.email_input.text()
        response = requests.post(f"{SERVER_URL}/get_key", json={"email": email})
        if response.status_code != 200:
            return    
        b_public_key_pem = response.json()['key']
        b_public_key = load_pem_public_key(b_public_key_pem.encode(), backend=default_backend())

        encrypted = b_public_key.encrypt(
            password.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        self_private_key = load_pem_private_key(
            self.private_key.encode(),
            password=None,
            backend=default_backend()
        )

        encrypted_and_signed = self_private_key.sign(
            encrypted, 
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        message = base64.b64encode(encrypted).decode()
        signature = base64.b64encode(encrypted_and_signed).decode()

        response = requests.post(f"{SERVER_URL}/generate_code", json={
            "username": username,
            "message": message,
            "signature": signature,
            "user_b_email": email,
            "public_key": self.public_key
        })
        
        if response.status_code == 200:
            code = response.json()['code']
            self.code_label.setText(f"Generated Code: {code}")
        

class UserBWindow(QWidget):
    def __init__(self, public_key, private_key):
        super().__init__()
        self.public_key = public_key
        self.private_key = private_key
        self.initUI()

    def initUI(self):
        self.code_input = QLineEdit(self)

        self.name_label = QLabel('User A\'s Name: ', self)

        self.submit_button = QPushButton('Submit Code', self)
        self.submit_button.clicked.connect(self.checkCode)

        self.result_label = QLabel(self)

        layout = QVBoxLayout()
        layout.addWidget(self.code_input)
        layout.addWidget(self.submit_button)
        layout.addWidget(self.name_label)
        layout.addWidget(self.result_label)

        self.setLayout(layout)
        self.setWindowTitle('User B Window')


    def checkCode(self):
        entered_code = self.code_input.text()
        response = requests.post(f"{SERVER_URL}/validate_code", json={"code": entered_code})
        
        if response.status_code == 200:
            status = response.json()['status']
            if status == 'success':
                username = response.json()['username']
                a_public_key_pem = response.json()['user_a_public_key']
                
                encrypted_messageb64 = response.json()['message']
                message = base64.b64decode(encrypted_messageb64)

                encrypted_signatureb64 = response.json()['signature']
                signature = base64.b64decode(encrypted_signatureb64)


                a_public_key = load_pem_public_key(a_public_key_pem.encode(), backend=default_backend())

                verified = a_public_key.verify(
                    signature,
                    message,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )

                private_key = load_pem_private_key(
                    self.private_key.encode(),
                    password=None,
                    backend=default_backend()
                )
                
                password = private_key.decrypt(
                    message,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                ).decode()

                self.name_label.setText(f"User A's Name: {username}")
                self.result_label.setText('Valid code')
                automated_login_and_wait(username, password, 10)
                delete_response = requests.post(f"{SERVER_URL}/delete_code", json={"code": entered_code})


            else:
                self.result_label.setText('Invalid code')
                self.name_label.setText("User A's Name: ")

    

def main():
    app = QApplication(sys.argv)
    home_window = HomeWindow()
    home_window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()