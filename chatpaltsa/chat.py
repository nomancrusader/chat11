from flask import Flask, render_template, redirect, url_for, request, session
from flask_socketio import SocketIO, emit
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Change this to a random secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chatapp.db'
db = SQLAlchemy(app)
socketio = SocketIO(app)

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# Message Model
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='messages')

# Create the database tables
with app.app_context():
    db.create_all()

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])  # No method specified
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        print(f"Attempting to log in user: {username}")  # Debug print
        if user:
            print(f"User found: {user.username}")  # Debug print
            if check_password_hash(user.password, password):
                session['user_id'] = user.id
                print(f"Login successful for user: {username}")  # Debug print
                return redirect(url_for('chat'))
            else:
                print("Incorrect password")  # Debug print
        else:
            print("User not found")  # Debug print
    return render_template('login.html')

@app.route('/chat')
def chat():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Fetch chat history
    messages = Message.query.all()
    return render_template('chat.html', messages=messages)

@socketio.on('message')
def handle_message(data):
    msg_content = data['msg']
    user_id = session['user_id']
    message = Message(user_id=user_id, content=msg_content)
    db.session.add(message)
    db.session.commit()
    emit('message', {'msg': msg_content, 'user': User.query.get(user_id).username}, broadcast=True)

if __name__ == '__main__':
    socketio.run(app, debug=True)
