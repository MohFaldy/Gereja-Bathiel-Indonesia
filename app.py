import os
import logging
from logging.handlers import RotatingFileHandler

from flask import Flask, render_template, redirect, url_for
from flask_login import LoginManager, current_user, login_required
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
from flask_wtf.csrf import CSRFProtect

# Blueprints
from auth import auth_bp
from admin_routes import admin_bp
from staff_routes import staff_bp
from user_routes import user_bp
from models import db, User, bcrypt, mail


# =======================================================
# 1. LOAD ENVIRONMENT VARIABLES
# =======================================================
load_dotenv()


# =======================================================
# 2. CREATE APP
# =======================================================
app = Flask(__name__)

# CSRF Protection
csrf = CSRFProtect(app)

app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "dev-secret-key")
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    "DATABASE_URL",
    "mysql+pymysql://root:@localhost/db_gereja"
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Mail Configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'in-v3.mailjet.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'true').lower() in ['true', '1', 't']
app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL', 'false').lower() in ['true', '1', 't']
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME') # <-- ISI DI FILE .env
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD') # <-- ISI DI FILE .env
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', app.config['MAIL_USERNAME'])

# Peringatan jika kredensial email tidak diatur
if not app.config.get('MAIL_USERNAME') or not app.config.get('MAIL_PASSWORD'):
    app.logger.warning(
        "PERINGATAN: MAIL_USERNAME atau MAIL_PASSWORD tidak diatur di file .env. Fitur email tidak akan berfungsi."
    )

# =======================================================
# 3. INIT EXTENSIONS
# =======================================================
db.init_app(app)
bcrypt.init_app(app)
mail.init_app(app)

# Session Hardening
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = "Lax"
if os.getenv("FLASK_DEBUG", "0") == "0":
    app.config['SESSION_COOKIE_SECURE'] = True


# =======================================================
# 4. SECURITY: TALISMAN (Secure Headers + CSP)
# =======================================================
csp = {
    'default-src': ["'self'"],
    'style-src': [
        "'self'",
        "'unsafe-inline'",           # Tailwind CDN requires inline styles
        "https://cdn.jsdelivr.net",
        "https://fonts.googleapis.com"
    ],
    'script-src': [
        "'self'",
        "https://cdn.jsdelivr.net",
    ],
    'font-src': [
        "'self'",
        "https://fonts.gstatic.com",
    ],
}

Talisman(
    app,
    content_security_policy=csp,
    force_https=(os.getenv("FLASK_DEBUG", "0") == "0")
)


# =======================================================
# 5. SECURITY: RATE LIMITING
# =======================================================
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)


# =======================================================
# 6. LOGGING
# =======================================================
if not os.path.exists("logs"):
    os.makedirs("logs")

handler = RotatingFileHandler(
    "logs/app.log",
    maxBytes=2 * 1024 * 1024,   # 2 MB
    backupCount=5
)
handler.setLevel(logging.INFO)
app.logger.addHandler(handler)


# =======================================================
# 7. LOGIN MANAGER
# =======================================================
login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# =======================================================
# COMMANDS
# =======================================================
@app.cli.command("init-db")
def init_db_command():
    """Membuat tabel database."""
    db.create_all()
    print("✅ Tabel database berhasil dibuat.")



# =======================================================
# 8. REGISTER BLUEPRINTS
# =======================================================
app.register_blueprint(auth_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(staff_bp)
app.register_blueprint(user_bp)


# =======================================================
# 9. ROUTES
# =======================================================
@app.route('/home')
def home():
    """Halaman utama yang mengarahkan ke login jika belum masuk."""
    # Selalu arahkan ke dashboard utama. Decorator @login_required akan menangani sisanya.
    return redirect(url_for('dashboard'))

@app.route('/') # Route ini sekarang menjadi dashboard utama
@login_required
def dashboard():
    """Route utama yang mengarahkan pengguna ke dashboard yang sesuai dengan perannya."""
    if current_user.role == "admin":
        return render_template("admin/admin_dashboard.html")
    elif current_user.role == "staff":
        return render_template("staff/staff_dashboard.html")
    return render_template("user/user_dashboard.html")


# @app.route('/admin/dashboard')
# @login_required
# def dashboard_admin():
#     if current_user.role != 'admin':
#         return redirect(url_for("dashboard"))
#     return render_template("admin/admin_dashboard.html")


# =======================================================
# 10. RUN SERVER
# =======================================================
if __name__ == '__main__':
    # with app.app_context():
    #     db.create_all()

    app.run(debug=True)
