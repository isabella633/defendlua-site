from flask import Flask, render_template, request, jsonify, redirect, url_for
import secrets
import hashlib
from datetime import datetime

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# In-memory storage
protected_codes = {}
access_logs = {}

# ---------------- ROUTES ----------------

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/protect', methods=['POST'])
def protect_code():
    code = request.form.get('code', '')
    if not code:
        return jsonify({'error': 'No code provided'}), 400

    raw_token = secrets.token_bytes(64) 
    code_id = hashlib.sha512(raw_token).hexdigest()
    protected_codes[code_id] = {
        'code': code,
        'created_at': datetime.now().isoformat(),
        'access_count': 0
    }
    access_logs[code_id] = []

    protected_url = f"{request.host_url}view/{code_id}"
    loadstring_url = f"{request.host_url}api/loadstring/{code_id}"

    return jsonify({
        'success': True,
        'protected_url': protected_url,
        'loadstring_url': loadstring_url,
        'code_id': code_id
    })

@app.route('/view/<code_id>')
def view_code(code_id):
    if code_id not in protected_codes:
        return render_template('not_found.html'), 404

    client_ip = request.remote_addr
    access_logs[code_id].append({
        'ip': client_ip,
        'timestamp': datetime.now().isoformat(),
        'user_agent': request.headers.get('User-Agent', 'Unknown'),
        'access_type': 'web_view'
    })

    code_data = protected_codes[code_id]
    return render_template('owner_view.html',
                           code=code_data['code'],
                           code_id=code_id,
                           access_logs=access_logs[code_id])

@app.route('/api/loadstring/<code_id>')
def get_loadstring(code_id):
    if code_id not in protected_codes:
        return "-- Error: Code not found", 404

    client_ip = request.remote_addr
    access_logs[code_id].append({
        'ip': client_ip,
        'timestamp': datetime.now().isoformat(),
        'user_agent': request.headers.get('User-Agent', 'Unknown'),
        'access_type': 'loadstring_execution'
    })

    protected_codes[code_id]['access_count'] += 1
    code_data = protected_codes[code_id]
    return code_data['code'], 200, {'Content-Type': 'text/plain'}

# ---------- NEW EDIT ROUTE ----------

@app.route('/edit/<code_id>', methods=['GET', 'POST'])
def edit_code(code_id):
    if code_id not in protected_codes:
        return render_template('not_found.html'), 404

    if request.method == 'POST':
        new_code = request.form.get('code', '')
        if not new_code.strip():
            return jsonify({'error': 'No code provided'}), 400

        # Update code
        protected_codes[code_id]['code'] = new_code
        protected_codes[code_id]['updated_at'] = datetime.now().isoformat()

        # Redirect back to dashboard
        return redirect(url_for('view_code', code_id=code_id))

    # GET → show edit page
    code_data = protected_codes[code_id]
    return render_template('edit.html',
                           code=code_data['code'],
                           code_id=code_id)

# ---------------- MAIN ----------------

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
