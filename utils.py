import re
from markupsafe import escape

# ================================
# SANITASI INPUT (HIGH SECURITY)
# ================================
def sanitize_input(text):
    """Membersihkan input dari karakter berbahaya, HTML tag, XSS, dsb."""
    if text is None:
        return ""

    cleaned = escape(text)                        # cegah XSS
    cleaned = re.sub(r'[\x00-\x1f\x7f]', '', cleaned)  # buang karakter aneh
    cleaned = cleaned[:255]

    return cleaned.strip()

# ================================
# VALIDASI USERNAME
# ================================
def validate_username(username):
    if not username:
        return False
    pattern = r'^[A-Za-z0-9_]{3,30}$'
    return bool(re.match(pattern, username))

# ================================
# VALIDASI PASSWORD
# ================================
def validate_password(password):
    return password is not None and len(password) >= 6

# ================================
# VALIDASI ROLE
# ================================
def validate_role(role):
    allowed = ["admin", "staff", "user"]
    return role in allowed

# ================================
# SANITASI INT
# ================================
def sanitize_int(value):
    try:
        return int(value)
    except:
        return None

# ================================
# SANITASI TANGGAL
# ================================
def sanitize_date(value):
    if value is None:
        return None
    if re.match(r"^\d{4}-\d{2}-\d{2}$", value):
        return value
    return None

# ================================
# CEK APAKAH ADMIN SUDAH ADA
# ================================
from models import User

def admin_exists():
    """Cek apakah admin sudah ada di database (hanya 1 admin diperbolehkan)."""
    return User.query.filter_by(role="admin").first() is not None
