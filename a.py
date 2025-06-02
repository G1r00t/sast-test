import sqlite3
import re
from typing import Optional, List, Dict, Any

class DatabaseManager:
    def __init__(self, db_path: str = ":memory:"):
        self.conn = sqlite3.connect(db_path)
        self.setup_database()
    
    def setup_database(self):
        """Create a sample users table for demonstration"""
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                email TEXT NOT NULL,
                role TEXT DEFAULT 'user'
            )
        ''')
        
        # Insert sample data
        sample_users = [
            ('admin', 'admin@example.com', 'admin'),
            ('john_doe', 'john@example.com', 'user'),
            ('jane_smith', 'jane@example.com', 'user'),
            ('bob_wilson', 'bob@example.com', 'user')
        ]
        
        cursor.executemany(
            'INSERT OR IGNORE INTO users (username, email, role) VALUES (?, ?, ?)',
            sample_users
        )
        self.conn.commit()

    def vulnerable_get_user(self, username: str) -> List[Dict[str, Any]]:
        """
        VULNERABLE FUNCTION - SQL Injection possible
        This function directly concatenates user input into SQL query
        SAST tools will flag this as a security vulnerability
        """
        cursor = self.conn.cursor()
        
        # VULNERABLE: Direct string concatenation - NO SANITIZATION
        query = f"SELECT * FROM users WHERE username = '{username}'"
        print(f"Executing vulnerable query: {query}")
        
        try:
            cursor.execute(query)
            columns = [description[0] for description in cursor.description]
            results = cursor.fetchall()
            return [dict(zip(columns, row)) for row in results]
        except Exception as e:
            print(f"Database error: {e}")
            return []

    def secure_get_user_with_sanitization(self, username: str) -> List[Dict[str, Any]]:
        """
        SECURE FUNCTION - Manual sanitization before parameterized query
        Even though this uses parameterized queries, SAST tools might still flag
        the sanitization logic as potentially problematic
        """
        cursor = self.conn.cursor()
        
        # SANITIZATION: Clean the input before using it
        sanitized_username = self._sanitize_input(username)
        
        # Use parameterized query (secure)
        query = "SELECT * FROM users WHERE username = ?"
        print(f"Executing secure query with sanitized input: {query}")
        print(f"Original input: '{username}' -> Sanitized: '{sanitized_username}'")
        
        try:
            cursor.execute(query, (sanitized_username,))
            columns = [description[0] for description in cursor.description]
            results = cursor.fetchall()
            return [dict(zip(columns, row)) for row in results]
        except Exception as e:
            print(f"Database error: {e}")
            return []

    def _sanitize_input(self, user_input: str) -> str:
        """
        Input sanitization function
        SAST tools might flag this as they detect SQL-related string manipulation
        """
        if not user_input:
            return ""
        
        # Remove common SQL injection characters and keywords
        # Note: This is for demonstration - in practice, parameterized queries are preferred
        dangerous_chars = ["'", '"', ";", "--", "/*", "*/", "xp_", "sp_"]
        dangerous_keywords = ["DROP", "DELETE", "INSERT", "UPDATE", "UNION", "SELECT", "EXEC"]
        
        sanitized = user_input
        
        # Remove dangerous characters
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, "")
        
        # Remove dangerous keywords (case insensitive)
        for keyword in dangerous_keywords:
            pattern = re.compile(re.escape(keyword), re.IGNORECASE)
            sanitized = pattern.sub("", sanitized)
        
        # Remove extra whitespace
        sanitized = re.sub(r'\s+', ' ', sanitized).strip()
        
        return sanitized

    def properly_secure_get_user(self, username: str) -> List[Dict[str, Any]]:
        """
        PROPERLY SECURE FUNCTION - Uses parameterized queries without manual sanitization
        This is the recommended approach and should not be flagged by SAST tools
        """
        cursor = self.conn.cursor()
        
        # Proper parameterized query - no string concatenation or manual sanitization needed
        query = "SELECT * FROM users WHERE username = ?"
        print(f"Executing properly secure query: {query}")
        
        try:
            cursor.execute(query, (username,))
            columns = [description[0] for description in cursor.description]
            results = cursor.fetchall()
            return [dict(zip(columns, row)) for row in results]
        except Exception as e:
            print(f"Database error: {e}")
            return []

    def close(self):
        """Close database connection"""
        self.conn.close()


def demonstrate_sql_injection():
    """
    Demonstration function showing different approaches
    """
    db = DatabaseManager()
    
    print("=" * 60)
    print("SQL Injection Demonstration")
    print("=" * 60)
    
    # Normal usage
    print("\n1. Normal usage:")
    print("Searching for user 'john_doe'")
    
    print("\n--- Vulnerable Function ---")
    result1 = db.vulnerable_get_user("john_doe")
    print(f"Results: {result1}")
    
    print("\n--- Secure Function with Sanitization ---")
    result2 = db.secure_get_user_with_sanitization("john_doe")
    print(f"Results: {result2}")
    
    print("\n--- Properly Secure Function ---")
    result3 = db.properly_secure_get_user("john_doe")
    print(f"Results: {result3}")
    
    # Malicious input attempt
    print("\n" + "="*60)
    print("2. Malicious input attempt:")
    malicious_input = "admin' OR '1'='1"
    print(f"Attempting SQL injection with: {malicious_input}")
    
    print("\n--- Vulnerable Function (will be exploited) ---")
    result1 = db.vulnerable_get_user(malicious_input)
    print(f"Results: {len(result1)} users returned (should be 1, but shows all)")
    
    print("\n--- Secure Function with Sanitization (protected) ---")
    result2 = db.secure_get_user_with_sanitization(malicious_input)
    print(f"Results: {len(result2)} users returned")
    
    print("\n--- Properly Secure Function (protected) ---")
    result3 = db.properly_secure_get_user(malicious_input)
    print(f"Results: {len(result3)} users returned")
    
    db.close()


if __name__ == "__main__":
    demonstrate_sql_injection()

