import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from models import db, User, ProtectedCode, AccessLog
from dotenv import load_dotenv


load_dotenv()




def create_app():
app = Flask(__name__)


app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


db.init_app(app)


login_manager = LoginManager(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
return User.query.get(int(user_id))


# ---------- CLI: initialize DB ----------
@app.cli.command('init-db')
def init_db():
with app.app_context():
db.create_all()
print('✅ Database initialized')


# ---------- Routes ----------can you
@app.route('/')
def index():
return render_template('index.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
if request.method == 'POST':
username = request.form.get('username', '').strip()
password = request.form.get('password', '')


if not username or not password:
flash('Username and password required', 'danger')
return redirect(url_for('signup'))


if User.query.filter_by(username=username).first():
flash('Username already exists', 'warning')
return redirect(url_for('signup'))


user = User(username=username)
user.set_password(password)
db.session.add(user)
db.session.commit()
flash('Account created! Please log in.', 'success')
return redirect(url_for('login'))
return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
if request.method == 'POST':
username = request.form.get('username', '').strip()
password = request.form.get('password', '')


user = User.query.filter_by(username=username).first()
if user and user.check_password(password):
login_user(user)
return redirect(url_for('dashboard'))
flash('Invalid credentials', 'danger')
return render_template('login.html')


app.run(debug=True)
