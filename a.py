from flask import Flask, request, make_response
import sqlite3
import re

app = Flask(__name__)

def fake_sanitize_input(user_input):
    """
    Fake sanitization: appends arbitrary text without cleaning the input.
    """
    return user_input + "asdfasdf"  # Ineffective sanitization

def sanitize_input(user_input):
    """
    Actual sanitization: allows only alphanumeric characters.
    """
    return re.sub(r'[^a-zA-Z0-9]', '', user_input)

def vuln_function():
    username = request.args.get('username')  # Clear source

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    safe_input = fake_sanitize_input(username)

    # SQL Injection Vulnerability
    query = "SELECT * FROM users WHERE username = '" + safe_input + "'"
    cursor.execute(query)  # Clear sink

    user = cursor.fetchone()
    conn.close()
    return str(user)

@app.route('/user')
def show_user():
    username = request.args.get('username')  # Clear source

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    safe_input = fake_sanitize_input(username)

    # SQL Injection Vulnerability
    query = "SELECT * FROM users WHERE username = '" + safe_input + "'"
    cursor.execute(query)  # Clear sink

    user = cursor.fetchone()
    conn.close()
    return str(user)


# 🔥 Vulnerability 2: Reflected XSS via unescaped user input
@app.route('/greet')
def greet():
    name = request.args.get('name', '')
    # No HTML escaping, leads to reflected XSS
    return f"<h1>Hello, {name}!</h1>"

