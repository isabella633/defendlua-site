import os
import re
import base64
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from models import db, User, ProtectedCode, AccessLog
from dotenv import load_dotenv

load_dotenv()

# --------- simple obfuscator (demo-level) ---------
_strip_comments = re.compile(r"--\s?.*$", re.MULTILINE)

def obfuscate_lua(src: str) -> str:
    """Very basic demo: strip line comments and base64-wrap the payload.
    This is NOT strong security. Replace with a real obfuscator if needed.
    """
    cleaned = _strip_comments.sub("", src)
    b64 = base64.b64encode(cleaned.encode("utf-8")).decode("ascii")
    loader = (
        "local b64='" + b64 + "'\n"
        "local s=game:GetService('HttpService'):Base64Decode(b64)\n"
        "local f=loadstring(s)\n"
        "if f then return f() end"
    )
    return loader


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

    # ---------- Routes ----------
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

        # find and check
            user = User.query.filter_by(username=username).first()
            if user and user.check_password(password):
                login_user(user)
                return redirect(url_for('dashboard'))
            flash('Invalid credentials', 'danger')
        return render_template('login.html')

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        return redirect(url_for('index'))

    @app.route('/dashboard')
    @login_required
    def dashboard():
        codes = ProtectedCode.query.filter_by(owner_id=current_user.id).order_by(ProtectedCode.created_at.desc()).all()
        return render_template('dashboard.html', codes=codes)

    @app.route('/protect', methods=['POST'])
    @login_required
    def protect():
        code = request.form.get('code', '').strip()
        if not code:
            return jsonify({ 'success': False, 'error': 'No code submitted.' }), 400

        pc = ProtectedCode(code=code, owner_id=current_user.id, create_ip=request.remote_addr)
        db.session.add(pc)
        db.session.commit()

        return jsonify({
            'success': True,
            'protected_url': url_for('view_code', uid=pc.uuid, _external=True),
            'loadstring_url': url_for('raw_code', uid=pc.uuid, _external=True)
        })

    @app.route('/obfuscate', methods=['POST'])
    @login_required
    def obfuscate():
        code = request.form.get('code', '').strip()
        if not code:
            return jsonify({ 'success': False, 'error': 'No code submitted.' }), 400
        try:
            obf = obfuscate_lua(code)
            return jsonify({ 'success': True, 'obfuscated_code': obf })
        except Exception as e:
            return jsonify({ 'success': False, 'error': str(e) }), 500

    def maybe_log_access(pc: ProtectedCode, path: str):
        if os.getenv('LOG_IP_ACCESS', 'false').lower() == 'true':
            log = AccessLog(code=pc, path=path, ip=request.remote_addr, user_agent=request.headers.get('User-Agent', ''))
            db.session.add(log)
            db.session.commit()

    @app.route('/code/<uid>')
    def view_code(uid):
        pc = ProtectedCode.query.filter_by(uuid=uid).first_or_404()
        maybe_log_access(pc, 'code')
        return render_template('code_view.html', pc=pc)

    @app.route('/raw/<uid>')
    def raw_code(uid):
        pc = ProtectedCode.query.filter_by(uuid=uid).first_or_404()
        maybe_log_access(pc, 'raw')
        return pc.code, 200, { 'Content-Type': 'text/plain; charset=utf-8' }

    # Owner-only delete/edit (simple examples)
    @app.route('/code/<uid>/delete', methods=['POST'])
    @login_required
    def delete_code(uid):
        pc = ProtectedCode.query.filter_by(uuid=uid).first_or_404()
        if pc.owner_id != current_user.id:
            abort(403)
        db.session.delete(pc)
        db.session.commit()
        flash('Code deleted.', 'success')
        return redirect(url_for('dashboard'))

    @app.route('/code/<uid>/update', methods=['POST'])
    @login_required
    def update_code(uid):
        pc = ProtectedCode.query.filter_by(uuid=uid).first_or_404()
        if pc.owner_id != current_user.id:
            abort(403)
        new_code = request.form.get('code', '').strip()
        if not new_code:
            flash('Code cannot be empty.', 'danger')
            return redirect(url_for('view_code', uid=uid))
        pc.code = new_code
        db.session.commit()
        flash('Code updated.', 'success')
        return redirect(url_for('view_code', uid=uid))

    return app


# For Gunicorn: `web: gunicorn 'app:create_app()'`
app = create_app()
