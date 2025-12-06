from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from flask_bcrypt import Bcrypt
from flask_mail import Mail

db = SQLAlchemy()
bcrypt = Bcrypt()
mail = Mail()


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')
    is_verified = db.Column(db.Boolean, nullable=False, default=False)

    # Kolom untuk 2FA (akan kita gunakan di Tahap 2)
    otp_secret = db.Column(db.String(16), nullable=True)

    def __repr__(self):
        return f'<User {self.username}>'

class Jemaat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nama = db.Column(db.String(150), nullable=False)
    tanggal_lahir = db.Column(db.Date, nullable=True)
    jenis_kelamin = db.Column(db.String(20), nullable=True)
    alamat = db.Column(db.String(255), nullable=True)
    no_hp = db.Column(db.String(20), nullable=True)

    def __repr__(self):
        return f'<Jemaat {self.nama}>'