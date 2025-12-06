from app import app  # pastikan ini sesuai dengan nama file utama Flask kamu
from models import db

with app.app_context():
    db.drop_all()
    db.create_all()
    print("✅ Database berhasil direset dan dibuat ulang!")
