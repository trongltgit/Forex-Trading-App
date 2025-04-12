from flask import Flask, render_template, request, redirect, session, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from datetime import datetime
import os
import csv

# ==== App config ====
app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blotter.db'
db = SQLAlchemy(app)

# ==== Mã hóa dữ liệu ====
key = Fernet.generate_key()
fernet = Fernet(key)

# ==== Models ====
class User(db.Model):
    id = db.Column(db.String(100), primary_key=True)  # đã mã hóa
    password_hash = db.Column(db.String(200))         # đã hash
    role = db.Column(db.String(20))                   # 'user_phong' / 'pth'

class Deal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    effective_date = db.Column(db.LargeBinary)
    currency_buy = db.Column(db.LargeBinary)
    currency_sell = db.Column(db.LargeBinary)
    amount = db.Column(db.LargeBinary)
    asked_rate = db.Column(db.LargeBinary)
    purpose = db.Column(db.LargeBinary)
    note = db.Column(db.LargeBinary)
    status = db.Column(db.String(20), default="pending")
    response_rate = db.Column(db.LargeBinary, nullable=True)
    requester_id = db.Column(db.String(100))

# ==== Routes ====
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    user_id = request.form['user_id']
    password = request.form['password']
    all_users = User.query.all()
    for user in all_users:
        try:
            decrypted_id = fernet.decrypt(user.id.encode()).decode()
            if decrypted_id == user_id and check_password_hash(user.password_hash, password):
                session['user_id'] = user.id
                session['role'] = user.role
                return redirect('/dashboard')
        except Exception as e:
            print(f"Error: {e}")
            continue
    return 'Sai thông tin đăng nhập'

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/')
    role = session['role']
    if role == 'user_phong':
        return render_template('dashboard.html', role='user_phong')
    elif role == 'pth':
        deals = Deal.query.filter_by(status="pending").all()
        return render_template('dashboard.html', role='pth', deals=deals, fernet=fernet)

@app.route('/submit-deal', methods=['POST'])
def submit_deal():
    def enc(val): return fernet.encrypt(val.encode())
    deal = Deal(
        effective_date=enc(request.form['effective_date']),
        currency_buy=enc(request.form['currency_buy']),
        currency_sell=enc(request.form['currency_sell']),
        amount=enc(request.form['amount']),
        asked_rate=enc(request.form['asked_rate']),
        purpose=enc(request.form['purpose']),
        note=enc(request.form['note']),
        requester_id=session['user_id']
    )
    db.session.add(deal)
    db.session.commit()
    return redirect('/dashboard')

@app.route('/reply-deal/<int:deal_id>', methods=['POST'])
def reply_deal(deal_id):
    deal = Deal.query.get(deal_id)
    deal.response_rate = fernet.encrypt(request.form['response_rate'].encode())
    deal.status = request.form['decision']
    db.session.commit()
    return redirect('/dashboard')

@app.route('/download-report')
def download_report():
    if 'role' not in session or session['role'] != 'pth':
        return redirect('/')
    
    deals = Deal.query.filter(Deal.status != 'pending').all()
    filename = 'report.csv'
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Ngày', 'Mua', 'Bán', 'Số lượng', 'Tỷ giá hỏi', 'Tỷ giá trả lời', 'Trạng thái'])
        for d in deals:
            writer.writerow([ 
                fernet.decrypt(d.effective_date).decode(),
                fernet.decrypt(d.currency_buy).decode(),
                fernet.decrypt(d.currency_sell).decode(),
                fernet.decrypt(d.amount).decode(),
                fernet.decrypt(d.asked_rate).decode(),
                fernet.decrypt(d.response_rate).decode() if d.response_rate else '',
                d.status
            ])
    return send_file(filename, as_attachment=True)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

# ==== Khởi tạo user mẫu ====
@app.before_request
def init_db():
    if not db.engine.has_table('user'):
        db.create_all()
        if not User.query.first():
            u1 = User(id=fernet.encrypt("phong1".encode()).decode(),
                      password_hash=generate_password_hash("123"),
                      role='user_phong')
            u2 = User(id=fernet.encrypt("pth1".encode()).decode(),
                      password_hash=generate_password_hash("123"),
                      role='pth')
            db.session.add_all([u1, u2])
            db.session.commit()


if __name__ == '__main__':
    app.run(debug=True)
