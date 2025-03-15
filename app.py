from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import requests
import sys

app = Flask(__name__)
app.secret_key = "weak-secret-key"

def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

#Broken Access Control
@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html') 

#Insecure Design
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        #Cryptographic Failures
        password = request.form['password']

        try:
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
            conn.close()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists!', 'danger')

    return render_template('register.html')

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        #Injection
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        print(f"Executing query: {query}") 
        cursor.execute(query)
        user = cursor.fetchone()
        conn.close()

        if user:
            session['auth_token'] = "valid-user-session"
            response = make_response(redirect(url_for('dashboard')))
            response.set_cookie('auth_token', 'valid-user-session', httponly=True, secure=True)
            flash('Login successful!', 'success')
            return response
        else:
            flash('Invalid username or password', 'danger')

    return render_template('login.html')

#Server-Side Request Forgery (SSRF)
@app.route('/fetch_url', methods=['GET', 'POST'])
def fetch_url():
    response_text = ""
    if request.method == 'POST':
        target_url = request.form['url']
        try:
            response = requests.get(target_url) 
            response_text = response.text
        except Exception as e:
            response_text = f"Error fetching URL: {e}"
    return render_template('fetch_url.html', response_text=response_text)

@app.route('/admin')
def admin():
    return render_template('admin.html')

@app.route('/logout')
def logout():
    session.pop('auth_token', None)
    response = make_response(redirect(url_for('login')))
    response.set_cookie('auth_token', '', expires=0)
    flash('Logged out successfully!', 'info')
    return response

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000  # Set port dynamically
    init_db()
    app.run(host='0.0.0.0', port=port, debug=True)