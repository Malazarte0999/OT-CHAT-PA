from flask import Flask, render_template, redirect, url_for, request, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your_default_secret_key')

users = {
    'user1@example.com': {
        'password': generate_password_hash('password1'),
        'name': 'John Doe'
    },
    'user2@example.com': {
        'password': generate_password_hash('password2'),
        'name': 'Jane Smith'
    }
}

def initialize_session():
    if 'sent_messages_count' not in session:
        session['sent_messages_count'] = 0
    if 'received_messages_count' not in session:
        session['received_messages_count'] = 0
    if 'sent_messages' not in session:
        session['sent_messages'] = []

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        if email in users and check_password_hash(users[email]['password'], password):
            session['user'] = {
                'email': email,
                'name': users[email]['name']
            }
            initialize_session()
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid email or password', 'danger')
            return render_template('login.html')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        name = request.form['name']
        if email not in users:
            users[email] = {
                'password': generate_password_hash(password),
                'name': name
            }
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Email already registered', 'danger')
            return render_template('register.html')
    return render_template('register.html')

@app.route('/home', methods=['GET', 'POST'])
def home():
    if 'user' in session:
        initialize_session()
        if request.method == 'POST':
            recipient = request.form['recipient']
            subject = request.form['subject']
            message = request.form['message']
            session['sent_messages'].append({
                'id': len(session['sent_messages']) + 1,
                'sender': session['user']['email'],
                'recipient': recipient,
                'subject': subject,
                'message': message,
                'likes': 0  
            })
            session['sent_messages_count'] += 1
            flash('Message sent!', 'success')
            return redirect(url_for('home'))
        return render_template('homepage.html', user=session['user'],
                               sent_messages_count=session['sent_messages_count'],
                               received_messages_count=session['received_messages_count'],
                               sent_messages=session['sent_messages'])
    else:
        return redirect(url_for('login'))

@app.route('/view', methods=['GET'])
def view_messages():
    if 'user' in session:
        return render_template('view.html', sent_messages=session['sent_messages'])
    else:
        return redirect(url_for('login'))

@app.route('/edit/<int:message_id>', methods=['GET', 'POST'])
def edit_message(message_id):
    if 'user' in session:
        message = next((m for m in session['sent_messages'] if m['id'] == message_id), None)
        if message:
            if request.method == 'POST':
                message['recipient'] = request.form['recipient']
                message['subject'] = request.form['subject']
                message['message'] = request.form['message']
                flash('Message updated successfully!', 'success')
                return redirect(url_for('view_messages'))
            return render_template('edit_message.html', message=message)
        else:
            flash('Message not found', 'danger')
            return redirect(url_for('view_messages'))
    return redirect(url_for('login'))

@app.route('/delete/<int:message_id>', methods=['POST'])
def delete_message(message_id):
    if 'user' in session:
        session['sent_messages'] = [message for message in session['sent_messages'] if message['id'] != message_id]
        session['sent_messages_count'] -= 1
        flash('Message deleted successfully!', 'success')
        return redirect(url_for('view_messages'))
    else:
        return redirect(url_for('login'))

@app.route('/like/<int:message_id>', methods=['POST'])
def like_message(message_id):
    if 'user' in session:
        for message in session['sent_messages']:
            if message['id'] == message_id:
                if 'likes' not in message:
                    message['likes'] = 0  
                message['likes'] += 1  
                flash('Liked message!', 'success')
                return redirect(url_for('view_messages'))
        flash('Message not found', 'danger')
    else:
        flash('You must be logged in to like a message', 'danger')
    return redirect(url_for('login'))

@app.route('/comment/<int:message_id>', methods=['POST'])
def add_comment(message_id):
    if 'user' in session:
        comment = request.form['comment']
        for message in session['sent_messages']:
            if message['id'] == message_id:
                if 'comments' not in message:
                    message['comments'] = []  # Initialize comments list if it doesn't exist
                message['comments'].append(comment)
                flash('Comment added successfully!', 'success')
                return redirect(url_for('view_messages'))
        flash('Message not found', 'danger')
    else:
        flash('You must be logged in to comment on a message', 'danger')
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
