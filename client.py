from http.client import responses
import sys
import requests
import os
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QLineEdit, QVBoxLayout, QLabel

from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.firefox.service import Service
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import hashes
import base64
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from nacl.public import PrivateKey, PublicKey, Box
import nacl.encoding
import nacl.signing
from nacl.public import SealedBox

SERVER_URL = "https://dsd-project-afbb3ca3afdb.herokuapp.com/"
home_directory = os.path.expanduser('~')
geckodriver_path = os.path.join(home_directory, 'Downloads', 'DSD_Project_MacIntel', 'geckodriver')

def automated_login_and_wait(username, password, wait_time, platform):
    service = Service(executable_path=geckodriver_path)
    driver = webdriver.Firefox(service=service)

    if platform == 'Canvas':
        driver.get('https://login.bc.edu/nidp/idff/sso?id=19&sid=0&option=credential&sid=0&target=https%3A%2F%2Fservices.bc.edu%2Fcommoncore%2Fmyservices.do')
        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.ID, 'username')))
        driver.find_element(By.ID, 'username').send_keys(username)
        driver.find_element(By.ID, 'password').send_keys(password)
        driver.find_element(By.ID, 'password').send_keys(Keys.RETURN)

    elif platform == 'Facebook':
        driver.get('https://www.facebook.com/login/')
        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.ID, 'email')))
        driver.find_element(By.ID, 'email').send_keys(username)
        driver.find_element(By.ID, 'pass').send_keys(password)
        driver.find_element(By.ID, 'pass').send_keys(Keys.RETURN)

    elif platform == 'Instagram':
        driver.get('https://www.instagram.com/accounts/login/?hl=en')
        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.NAME, 'username')))
        driver.find_element(By.NAME, 'username').send_keys(username)
        driver.find_element(By.NAME, 'password').send_keys(password)
        driver.find_element(By.NAME, 'password').send_keys(Keys.RETURN)

    elif platform == 'LinkedIn':
        driver.get('https://www.linkedin.com/home')
        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.NAME, 'session_key')))
        driver.find_element(By.NAME, 'session_key').send_keys(username)
        driver.find_element(By.NAME, 'session_password').send_keys(password)
        driver.find_element(By.NAME, 'session_password').send_keys(Keys.RETURN)

    elif platform == 'Reddit':
        driver.get('https://www.reddit.com/login/')
        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.ID, 'login-username')))
        driver.find_element(By.ID, 'login-username').send_keys(username)
        driver.find_element(By.ID, 'login-password').send_keys(password)
        driver.find_element(By.ID, 'login-password').send_keys(Keys.RETURN)

    wait_time *= 60
    time.sleep(wait_time)
    driver.quit()


class HomeWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        user_a_button = QPushButton('Send Login Credentials', self)
        user_a_button.clicked.connect(self.beUserA)

        user_b_button = QPushButton('Recieve Login Credentials', self)
        user_b_button.clicked.connect(self.beUserB)

        self.email_input = QLineEdit(self)
        self.email_input.setPlaceholderText("Enter your email to register")

        layout = QVBoxLayout()
        layout.addWidget(self.email_input)
        layout.addWidget(user_a_button)
        layout.addWidget(user_b_button)

        self.setLayout(layout)
        self.setWindowTitle('Home')

    def beUserA(self):
        self.epublic_key, self.eprivate_key, self.npublic_key, self.nprivare_key = self.registerUser(0)
        self.user_a_window = UserAWindow(self.epublic_key, self.eprivate_key, self.npublic_key, self.nprivare_key )
        self.user_a_window.show()

    def beUserB(self):
        self.epublic_key, self.eprivate_key, self.npublic_key, self.nprivare_key = self.registerUser(1)
        self.user_b_window = UserBWindow(self.epublic_key, self.eprivate_key, self.npublic_key, self.nprivare_key )
        self.user_b_window.show()

    def registerUser(self, user):
        email = self.email_input.text()
        epublic_key, eprivate_key, nprivate_key, npublic_key  = self.generate_key_pair()
        epublic_key_serialized = epublic_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        eprivate_key_serialized = eprivate_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,  
            encryption_algorithm=serialization.NoEncryption()  
        )
        npublic_key_serialized = npublic_key.encode(encoder=nacl.encoding.Base64Encoder)
        nprivate_key_serialized = nprivate_key.encode(encoder=nacl.encoding.Base64Encoder)

        if user == 1:
            response = requests.post(f"{SERVER_URL}/register_user", json={"email": email, "public_key": base64.b64encode(npublic_key.encode()).decode('utf-8')})
        return epublic_key_serialized.decode(), eprivate_key_serialized.decode(), npublic_key, nprivate_key#npublic_key_serialized.decode(), nprivate_key_serialized.decode()

    def generate_key_pair(self):
        eprivate_key = ed25519.Ed25519PrivateKey.generate()
        epublic_key = eprivate_key.public_key()

        nprivate_key = PrivateKey.generate()
        npublic_key = nprivate_key.public_key
        return epublic_key, eprivate_key, nprivate_key, npublic_key


class UserAWindow(QWidget):
    def __init__(self, epublic_key, eprivate_key, npublic_key, nprivate_key):
        super().__init__()
        self.epublic_key = epublic_key
        self.eprivate_key = eprivate_key
        self.npublic_key = npublic_key
        self.nprivate_key = nprivate_key
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Send Credentials')
        self.setGeometry(100, 100, 500, 300)

        self.canvas_button = QPushButton('Canvas', self)
        self.canvas_button.clicked.connect(lambda: self.enableInputs("Canvas"))

        self.instagram_button = QPushButton('Instagram', self)
        self.instagram_button.clicked.connect(lambda: self.enableInputs("Instagram"))

        self.facebook_button = QPushButton('Facebook', self)
        self.facebook_button.clicked.connect(lambda: self.enableInputs("Facebook"))

        self.reddit_button = QPushButton('Reddit', self)
        self.reddit_button.clicked.connect(lambda: self.enableInputs("Reddit"))
        
        self.linkedin_button = QPushButton('LinkedIn', self)
        self.linkedin_button.clicked.connect(lambda: self.enableInputs("LinkedIn"))

        layout = QVBoxLayout()
        layout.addWidget(self.canvas_button)
        layout.addWidget(self.instagram_button)
        layout.addWidget(self.facebook_button)
        layout.addWidget(self.reddit_button)
        layout.addWidget(self.linkedin_button)

        self.setLayout(layout)

        self.username_input = QLineEdit(self)
        self.username_input.setPlaceholderText("Username")
        self.username_input.hide()

        self.password_input = QLineEdit(self)
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.Password) 
        self.password_input.hide()

        self.wait_time_input = QLineEdit(self)
        self.wait_time_input.setPlaceholderText("Wait Time (in minutes)")
        self.wait_time_input.hide()

        self.email_input = QLineEdit(self)
        self.email_input.setPlaceholderText("Email of Receiving Party")
        self.email_input.hide()

        self.generate_button = QPushButton('Generate Code', self)
        self.generate_button.clicked.connect(self.generateCode)
        self.generate_button.hide()

        self.code_label = QLabel(self)

        layout.addWidget(self.username_input)
        layout.addWidget(self.password_input)
        layout.addWidget(self.wait_time_input)
        layout.addWidget(self.email_input)
        layout.addWidget(self.generate_button)
        layout.addWidget(self.code_label)

        self.setLayout(layout)

    def enableInputs(self, platform):
        self.canvas_button.hide()
        self.instagram_button.hide()
        self.facebook_button.hide()
        self.reddit_button.hide()
        self.linkedin_button.hide()

        self.username_input.show()
        self.password_input.show()
        self.generate_button.show()
        self.email_input.show()
        self.wait_time_input.show()

        self.code_label.setText(f"Selected platform: {platform}")

    def generateCode(self):
        username = self.username_input.text()
        password = self.password_input.text()
        email = self.email_input.text()
        wait_time = self.wait_time_input.text() 
        platform = self.code_label.text().split(': ')[1] 

        response = requests.post(f"{SERVER_URL}/get_key", json={"email": email})
        if response.status_code != 200:
            return

        try:
            b_public_key= response.json()['key']
            b_public_key_bytes = base64.b64decode(b_public_key)
            b_public_key = PublicKey(b_public_key_bytes, encoder=nacl.encoding.RawEncoder)
        except:
            self.code_label.setText("User with that email was not found.")
            return

        box = SealedBox(b_public_key)
        encrypted_message = box.encrypt(f"{password}".encode())

        private_key_bytes = self.eprivate_key.encode()
        eprivate_key = load_pem_private_key(private_key_bytes, password=None, backend=default_backend())

        encrypted_and_signed = eprivate_key.sign(encrypted_message)

        message = base64.b64encode(encrypted_message).decode('utf-8')
        signature = base64.b64encode(encrypted_and_signed).decode('utf-8')

        response = requests.post(f"{SERVER_URL}/generate_code", json={
            "username": username,
            "message": message,
            "signature": signature,
            "user_b_email": email,
            "public_key": base64.b64encode(self.epublic_key.encode()).decode('utf-8'),
            "platform": platform,
            "wait_time": wait_time 
        })

        if response.status_code == 200:
            code = response.json()['code']
            self.code_label.setText(f"Code Sent!")
            #self.code_label.setText(f"Generated Code: {code}")
        

class UserBWindow(QWidget):
    def __init__(self, epublic_key, eprivate_key, npublic_key, nprivate_key):
        super().__init__()
        self.epublic_key = epublic_key
        self.eprivate_key = eprivate_key
        self.npublic_key = npublic_key
        self.nprivate_key = nprivate_key
        self.initUI()

    def initUI(self):
        self.code_input = QLineEdit(self)

        self.name_label = QLabel('', self)

        self.submit_button = QPushButton('Submit Code', self)
        self.submit_button.clicked.connect(self.checkCode)

        self.result_label = QLabel(self)

        layout = QVBoxLayout()
        layout.addWidget(self.code_input)
        layout.addWidget(self.submit_button)
        layout.addWidget(self.name_label)
        layout.addWidget(self.result_label)

        self.setLayout(layout)
        self.setWindowTitle('Receive Credentials')


    def checkCode(self):
        entered_code = self.code_input.text()
        response = requests.post(f"{SERVER_URL}/validate_code", json={"code": entered_code})

        if response.status_code == 200:
            status = response.json()['status']
            if status == 'success':
                username = response.json()['username']
                platform = response.json()['platform']
                wait_time = response.json()['wait_time']
                encrypted_messageb64 = response.json()['message']
                encrypted_signatureb64 = response.json()['signature']
                a_public_key_b64 = response.json()['user_a_public_key']

                message = base64.b64decode(encrypted_messageb64)
                signature = base64.b64decode(encrypted_signatureb64)
                a_public_key_bytes = base64.b64decode(a_public_key_b64)

                a_public_key = load_pem_public_key(a_public_key_bytes, backend=default_backend())

                try:
                    a_public_key.verify(signature, message)
                except Exception as e:
                    print("Signature verification failed:", e)
                    return

                sealed_box = SealedBox(self.nprivate_key)
                try:
                    password = sealed_box.decrypt(message).decode()
                except Exception as e:
                    print("Decryption failed:", e)
                    return

                self.name_label.setText("Sucess!")
                #self.name_label.setText(f"User A's Name: {username} on {platform} with wait time {wait_time} sec")
                self.result_label.setText('Valid code')
                automated_login_and_wait(username, password, int(wait_time), platform)

                delete_response = requests.post(f"{SERVER_URL}/delete_code", json={"code": entered_code})

            else:
                self.result_label.setText('Invalid code')
                #self.name_label.setText("User A's Name: ")

def main():
    app = QApplication(sys.argv)
    home_window = HomeWindow()
    home_window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
