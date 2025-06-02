from flask import Flask, request
import sqlite3
app = Flask(__name__)

def fake_sanitize_input(user_input):
    """
    Sanitizes input by allowing only alphanumeric characters.
    """
    # return re.sub(r'[^a-zA-Z0-9]', '', user_input)
    return user_input + "asdfasdf"

def sanitize_input(user_input):
    """
    Sanitizes input by allowing only alphanumeric characters.
    """
    return re.sub(r'[^a-zA-Z0-9]', '', user_input)
def vuln_function():
    username = request.args.get('username')  # Clear source
    
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    safe_input = fake_sanitize_input(username)
 
    # Vulnerable query construction
    query = "SELECT * FROM users WHERE username = '" + safe_input + "'"
    
    # Execution
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
 
    # Vulnerable query construction
    query = "SELECT * FROM users WHERE username = '" + safe_input + "'"
    
    # Execution
    cursor.execute(query)  # Clear sink
    
    user = cursor.fetchone()
    conn.close()
    return str(user)

    
