# Clark-Fields-Project

# Ultimate Goal

The ultimate goal of this project is to enhance user convenience and security in digital access by enabling a secure, time-limited sharing of user credentials without disclosing the actual password. This project aims to develop a robust system that automates the login process for trusted individuals under specific conditions, preserving the confidentiality of login credentials while ensuring full user control and auditability. The system will facilitate scenarios where temporary access is necessary, such as family members needing to manage accounts during emergencies or friends requiring access for collaborative tasks, without compromising the integrity and security of the user’s personal information.

## Target Audience

- **Family Households**: Need to share access to accounts for managing household utilities, streaming services, or emergency access to critical information.
- **Professional Freelancers and Small Business Owners**: Need to give temporary access to accounts for financial, operational, or administrative tasks to colleagues or assistants without handing over full control.
- **Educational Institutions and Students**: Require a system to share access to educational tools and resources temporarily for projects or assignments.
- **Elderly Users**: Might require assistance in managing their digital accounts and need a simple and secure method to grant access to caregivers or family members.
- **Tech-savvy Users**: Looking for a more secure way to manage multiple digital footprints and credentials efficiently, especially those who prioritize cybersecurity but also value convenience.

## Current Functionality

- **Automated Logins**: Automates the login process for multiple platforms using Selenium WebDriver.
- **Secure Credential Handling**: Uses modern cryptography to ensure secure transmission and storage of user credentials.
- **User Interface**: Provides a GUI for easy interaction with the application, allowing users to enter and manage their credentials.
- **Server Communication**: Handles requests between the client and the server securely, managing user data and authentication codes.

## Steps to Run the Project

1. Download `DSD_Project.zip` and unzip it.
2. In terminal, run: chmod +x ~/Downloads/DSD_Project/script.sh
3. Now run: ./script.sh
4. Register a user B.
5. Register a user A then walk through all the steps.

## Main Objects and Libraries

- **client.py**:
    - **Libraries**: Uses `http.client`, `sys`, `requests`, `PyQt5` for GUI, `selenium` for browser automation, `cryptography` and `nacl` for encryption and signing.
    - **Key Components**:
 - GUI elements for user interaction.
 - Web automation for tasks like login.
 - Encryption for secure data handling.
- **Interactions**:
 - The client interacts with the server via HTTP requests, sending and retrieving data.
 - The server responds with JSON-formatted data.
 - Secure communication is emphasized through the use of public key cryptography for data exchange and verification codes for user verification.

- **server.py**:
- **Libraries**: Utilizes `flask` for the web framework, `random` for generating codes, and `flask.jsonify` for sending JSON responses.
- **Key Components**:
 - RESTful endpoints to handle requests like user registration, key retrieval, and code generation/validation.
 - Database interactions for storing and retrieving data such as emails, public keys, and verification codes.

## Security Concerns and Mitigations

- **Security Concerns**:
- Data Interception: The transmission of sensitive information over the network could be intercepted.
- User Authentication: The system must ensure that the user is who they claim to be to prevent unauthorized access.
- Data Integrity: Ensuring the data has not been altered in transit.

- **Mitigation Strategies**:
- Encryption: Using libraries like `cryptography` and `nacl` to encrypt data helps protect sensitive information.
- HTTPS: The use of HTTPS (noted in the SERVER_URL) helps secure communication between client and server.
- Verification Codes: Employing verification codes sent to users’ emails to authenticate actions.

## Additional Work to Reach Ultimate Goals

- Enhancing User Interface: Further improvements could be made to the GUI for better user experience and functionality.
- Expanding Platform Coverage: Adding support for more platforms in the web automation part of the client code.
- Security Audits: Conducting thorough security audits and tests to find and fix potential vulnerabilities.
- Scalability Improvements: Optimizing both client and server code to handle a larger number of users smoothly.
- Additional Features: Implementing features like multi-factor authentication and more sophisticated user management.
