from werkzeug.security import generate_password_hash
import os
import sqlite3

DATABASE = 'database/users.db'
QUOTES = 'database/quotes.txt'

def db_init():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('DROP TABLE IF EXISTS quotes;')
        cursor.execute('DROP TABLE IF EXISTS users;')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                pubkey TEXT,
                is_admin INTEGER NOT NULL
            );
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS quotes (
                id INTEGER PRIMARY KEY,
                quote TEXT NOT NULL
            );
        ''')

        with open(QUOTES, 'r') as quotes_file:
            quotes = [(q.strip(),) for q in quotes_file.readlines()]
            cursor.executemany('INSERT INTO quotes (quote) VALUES (?)', quotes)

        admin_password_hash = generate_password_hash(os.getenv('ADMINPASS'))
        cursor.execute(
            "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
            ('saruman', admin_password_hash, 1)
        )
        user_password_hash = generate_password_hash('hobbit')
        cursor.execute(
            "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
            ('aragorn', user_password_hash, 0)
        )

        conn.commit()

def db_get_user_by_name(username):
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password_hash, is_admin FROM users WHERE username = ?", (username,))
        user_data = cursor.fetchone()
        return user_data

def db_get_user_by_id(user_id):
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password_hash, is_admin FROM users WHERE id = ?", (user_id,))
        user_data = cursor.fetchone()
        return user_data

def db_set_pubkey(user_id, publicKey):
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET pubkey = ? WHERE id = ?", (publicKey, user_id))
        conn.commit()

def db_get_pubkey(username):
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT pubkey FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        return result

def db_get_quotes():
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT quote FROM quotes")
        result = cursor.fetchall()
        return result

