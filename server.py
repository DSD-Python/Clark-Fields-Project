from flask import Flask, jsonify, request
import random
import json

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

app = Flask(__name__)

db_file = 'data.json'

def save_to_db(new_entry):
    data = load_from_db()
    data.append(new_entry)
    with open(db_file, 'w') as f:
        json.dump(data, f)

def load_from_db():
    try:
        with open(db_file, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return []

def delete_from_db(code):
    data = load_from_db()
    data = [entry for entry in data if entry.get('code') != code]
    with open(db_file, 'w') as f:
        json.dump(data, f)
    

def delete_email_from_db(email):
    data = load_from_db()
    print(data)
    data = [entry for entry in data if entry.get('email') != email]
    with open(db_file, 'w') as f:
        json.dump(data, f)
    data = load_from_db()
    print(data)

def send_email(receiver_email, subject, message):
    sender_email = "dsdacountsharing@gmail.com"
    password = "zzlw hmmj izho zpcr"

    msg = MIMEText(message)
    msg['Subject'] = subject
    msg['From'] = sender_email
    msg['To'] = receiver_email

    server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
    server.login(sender_email, password)
    server.sendmail(sender_email, receiver_email, msg.as_string())
    server.quit()

@app.route('/register_user', methods=['POST'])
def register_user():
    data = request.json
    email = data['email']
    public_key = data['public_key']
    data_list = load_from_db()
    for entry in data_list:
        if email == entry.get('email'):
            entry['public_key'] = public_key
            return jsonify({'status': 'success'})
    save_to_db({'email': email, 'public_key': public_key})

    return jsonify({'status': 'success'})

@app.route('/get_key', methods=['POST'])
def get_key():
    data = request.json
    email = data['email']

    data_list = load_from_db()
    for entry in data_list:
        if email == entry.get('email'):
            return jsonify({'status': 'success', 'key': entry.get('public_key')}) 
    return jsonify({'status': 'fail', 'key': None})
    

@app.route('/generate_code', methods=['POST'])
def generate_code():
    data = request.json
    username = data['username']
    message = data['message']
    signature = data['signature']
    user_b_email = data['user_b_email']
    user_a_public_key = data.get('public_key')
    platform = data.get('platform')  # New field
    wait_time = data.get('wait_time')  # New field
    code = str(random.randint(100000, 999999))

    save_to_db({'code': code, 'username': username, 'message': message, 'signature': signature,
                'user_a_public_key': user_a_public_key, 'platform': platform, 'wait_time': wait_time})
    
    delete_email_from_db(user_b_email)
    if user_b_email:
        send_email(user_b_email, "Verification Code", f"Your verification code is: {code}")

    return jsonify({'code': code})

@app.route('/validate_code', methods=['POST'])
def validate_code():
    data = request.json
    entered_code = data['code']

    data_list = load_from_db()
    for entry in data_list:
        if entered_code == entry.get('code'):
            return jsonify({'status': 'success', 'username': entry.get('username'), 'message': entry.get('message'),
                            'signature': entry.get('signature'), 'user_a_public_key': entry.get('user_a_public_key'),
                            'platform': entry.get('platform'), 'wait_time': entry.get('wait_time')})  # Include platform and wait time
    
    return jsonify({'status': 'fail', 'username': None, 'message': None})

@app.route('/delete_code', methods=['POST'])
def delete_code():
    data = request.json
    code = data['code']
    delete_from_db(code)
    return jsonify({'status': 'success'})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
