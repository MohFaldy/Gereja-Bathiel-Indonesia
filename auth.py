from flask import Blueprint, render_template, redirect, request, url_for, flash, current_app
from flask_login import login_user, logout_user, current_user
from models import User, db, bcrypt, mail
from utils import admin_exists
from threading import Thread
from mailjet_rest import Client
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Message
from forms import LoginForm, RegisterForm # Impor form yang baru dibuat
auth_bp = Blueprint('auth', __name__)

# ====================================================
#               FUNGSI HELPER EMAIL
# ====================================================
def generate_verification_token(email):
    """Membuat token aman untuk verifikasi email."""
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='email-verification-salt')

def send_async_email(app, msg):
    """Fungsi untuk mengirim email di background thread."""
    with app.app_context():
        try:
            # Inisialisasi Mailjet Client
            api_key = app.config['MAIL_USERNAME']
            api_secret = app.config['MAIL_PASSWORD']
            mailjet = Client(auth=(api_key, api_secret), version='v3.1')
            
            # Kirim email menggunakan HTTP API
            result = mailjet.send.create(data=msg)
            
            if result.status_code != 200:
                app.logger.error(f"Mailjet API Error: {result.status_code} - {result.json()}")
        except Exception as e:
            # Log error jika pengiriman di background gagal
            app.logger.error(f"Gagal mengirim email di background thread: {e}")


def send_verification_email(user_email):
    """Mempersiapkan dan mengirim email verifikasi menggunakan Mailjet HTTP API."""
    try:
        token = generate_verification_token(user_email)
        # _external=True untuk menghasilkan URL absolut (dengan domain)
        verify_url = url_for('auth.verify_email', token=token, _external=True)
        
        html = render_template('emails/verify_email.html', verify_url=verify_url)
        subject = "Verifikasi Akun Anda"
        # Buat payload data untuk Mailjet API
        # Ambil nama dan email dari MAIL_DEFAULT_SENDER
        sender_string = current_app.config['MAIL_DEFAULT_SENDER']
        sender_name = sender_string.split('<')[0].strip()
        sender_email = sender_string.split('<')[1].replace('>', '').strip()

        data = {
            'Messages': [{
                "From": {"Email": sender_email, "Name": sender_name},
                "To": [{"Email": user_email}],
                "Subject": subject,
                "HTMLPart": html
            }]
        }
        # Jalankan pengiriman email di thread terpisah
        app = current_app._get_current_object()
        thread = Thread(target=send_async_email, args=[app, data])
        thread.start()
    except Exception as e:
        current_app.logger.error(f"Gagal mengirim email verifikasi ke {user_email}: {e}")
        # Lemparkan kembali error jika persiapan email gagal (bukan saat pengiriman)
        raise e

# ====================================================
#               LOGIN
# ====================================================
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # Sanitasi input tidak lagi diperlukan karena WTForms melakukannya
        username = form.username.data
        password = form.password.data

        user = User.query.filter_by(username=username).first() # Query user

        if not user or not bcrypt.check_password_hash(user.password, password):
            flash("Username atau password salah!", "danger")
            return redirect(url_for('auth.login'))
        
        if not user.is_verified and not current_app.debug:
            flash('Akun Anda belum diverifikasi. Silakan cek email Anda untuk link verifikasi.', 'warning')
            return redirect(url_for('auth.login'))

        login_user(user)
        return redirect(url_for('dashboard'))

    return render_template("login.html", form=form)


# ====================================================
#               REGISTER
# ====================================================
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        # Semua validasi (format, duplikat) sudah ditangani oleh kelas RegisterForm
        username = form.username.data
        email = form.email.data
        password = form.password.data
        role = form.role.data

        # Admin hanya satu
        if role == "admin" and admin_exists():
            flash("Admin hanya boleh satu!", "danger")
            return render_template("register.html", form=form)

        try:
            # Hash password
            hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')

            # Buat user baru dan tambahkan ke session, tapi jangan commit dulu
            new_user = User(username=username, email=email, password=hashed_pw, role=role, is_verified=False)
            db.session.add(new_user)

            # Kirim email verifikasi SEBELUM commit ke database
            send_verification_email(new_user.email)

            # Jika pengiriman email berhasil, baru commit user ke database
            db.session.commit()
            flash("Registrasi berhasil! Silakan cek email Anda untuk menyelesaikan pendaftaran.", "success")
            return redirect(url_for('auth.login'))
        except Exception as e:
            db.session.rollback() # Batalkan penambahan user jika terjadi error
            flash("Gagal memproses pendaftaran. Pastikan email valid dan coba lagi.", "danger")


    # Tambahkan ini untuk debugging: Jika request adalah POST dan validasi gagal,
    # cetak error ke konsol untuk melihat apa yang salah.
    if request.method == 'POST' and form.errors:
        current_app.logger.warning(f"Kegagalan validasi form registrasi: {form.errors}")

    return render_template("register.html", form=form)


# ====================================================
#               VERIFIKASI EMAIL
# ====================================================
@auth_bp.route('/verify/<token>')
def verify_email(token):
    try:
        serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        email = serializer.loads(token, salt='email-verification-salt', max_age=3600) # Token valid selama 1 jam
    except:
        flash('Link verifikasi tidak valid atau sudah kedaluwarsa.', 'danger')
        return redirect(url_for('auth.login'))

    user = User.query.filter_by(email=email).first_or_404()
    user.is_verified = True
    db.session.commit()
    flash('Akun Anda telah berhasil diverifikasi! Silakan login.', 'success')
    return redirect(url_for('auth.login'))


# ====================================================
#               LOGOUT
# ====================================================
@auth_bp.route('/logout')
def logout():
    logout_user()
    flash("Anda telah logout.", "info")
    return redirect(url_for('home'))
