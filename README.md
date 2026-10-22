
# TrustVault – Secure Document Sharing System

## Project Overview

TrustVault is a Flask-based web application that provides secure document
uploading, sharing, permission management, and audit logging.

It uses role-based access control to restrict actions based on user roles
and document permissions.

## Features

- User login and logout
- Password hashing
- Role-based access control
- Secure document uploads
- File type restrictions and a 5 MB upload limit
- Document ownership and sharing
- Read and edit permission records
- Permission revocation
- Access-controlled document downloads
- SQLite database persistence
- Audit logs with timestamps
- Administrator-only audit dashboard
- Automated authorization tests using pytest

## Technologies Used

- Python
- Flask
- SQLite
- HTML and CSS
- JavaScript
- pytest

## Project Structure

    TrustVault/
    ├── app.py
    ├── test_app.py
    ├── trustvault.db
    ├── private_documents/
    └── templates/
        ├── login.html
        ├── dashboard.html
        ├── upload.html
        ├── share.html
        └── audit.html

## Installation

1. Install Python 3.
2. Open a terminal in the project directory.
3. Install the required packages:

       python -m pip install flask pytest

4. Start the application:

       python app.py

5. Open this address in your browser:

       http://127.0.0.1:5000

## Demo Accounts

For local testing only:

| Role | Username | Password |
|---|---|---|
| Administrator | admin | Admin123 |
| Document Owner | owner | Owner123 |
| Viewer | viewer | Viewer123 |

Change or remove demo credentials before any public deployment.

## Running Automated Tests

Run:

    python -m pytest -v

The tests check basic role restrictions, document uploads,
permission revocation, and administrator audit access.

## Security Notes

This project is a prototype and requires further security hardening
before production use.

Recommended improvements include CSRF protection, stronger secret-key
management, secure production configuration, comprehensive file
validation, and additional security tests.

The audit log is stored in SQLite and is not tamper-proof against someone
who can modify the database directly.
