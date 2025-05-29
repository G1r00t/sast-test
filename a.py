import hashlib
import random
import os
import requests

# Vulnerability 1: Use of insecure hash function (MD5)
# MD5 is cryptographically weak but may be acceptable for non-security purposes
def generate_file_hash(filename):
    with open(filename, 'rb') as f:
        file_hash = hashlib.md5(f.read()).hexdigest()
    return file_hash

# Vulnerability 2: Use of weak random number generator
# Using random instead of secrets module for generating tokens
def generate_reset_token():
    token = ''.join(random.choice('0123456789ABCDEF') for i in range(16))
    return token

# Vulnerability 3: Hardcoded credentials in code
# Test credentials that might be accidentally deployed
def connect_to_test_db():
    username = "test_user"
    password = "test_password123"  # Hardcoded credential
    # Code to connect to database
    return f"Connected to test DB as {username}"

# Vulnerability 4: Insecure HTTP usage
# Using HTTP instead of HTTPS for API requests
def fetch_user_data(user_id):
    response = requests.get(f"http://example.com/api/users/{user_id}")
    return response.json()

# Vulnerability 5: Potential path traversal issue
# Not properly sanitizing file paths from user input
def read_user_file(filename):
    base_dir = "/var/data/user_files/"
    file_path = os.path.join(base_dir, filename)
    try:
        with open(file_path, 'r') as f:
            return f.read()
    except FileNotFoundError:
        return "File not found"

# Example usage
if __name__ == "__main__":
    print(f"File hash: {generate_file_hash('example.txt')}")
    print(f"Reset token: {generate_reset_token()}")
    print(connect_to_test_db())
    print(f"User data: {fetch_user_data(123)}")
    print(f"File contents: {read_user_file('notes.txt')}")
