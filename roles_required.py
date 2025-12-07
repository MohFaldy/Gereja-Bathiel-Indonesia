from flask import redirect, url_for, flash
from flask_login import current_user
from functools import wraps

def require_role(role):
    """Decorator untuk membatasi akses ke sebuah route hanya untuk role tertentu."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                flash("Anda harus login untuk mengakses halaman ini.", "warning")
                return redirect(url_for('auth.login'))
            if current_user.role != role:
                flash("Anda tidak memiliki izin untuk mengakses halaman ini.", "danger")
                return redirect(url_for('dashboard'))
            return func(*args, **kwargs)
        return wrapper
    return decorator
