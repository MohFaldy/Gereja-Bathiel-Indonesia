from flask import redirect, url_for
from flask_login import current_user

def require_role(role):
    def decorator(func):
        def wrapper(*args, **kwargs):
            if current_user.role != role:
                return redirect(url_for('dashboard'))
            return func(*args, **kwargs)
        return wrapper
    return decorator


def admin_only(func):
    def wrapper(*args, **kwargs):
        if current_user.role != "admin":
            return redirect(url_for('dashboard'))
        return func(*args, **kwargs)
    return wrapper

def staff_only(func):
    def wrapper(*args, **kwargs):
        if current_user.role != "staff":
            return redirect(url_for('dashboard'))
        return func(*args, **kwargs)
    return wrapper

def user_only(func):
    def wrapper(*args, **kwargs):
        if current_user.role != "user":
            return redirect(url_for('dashboard'))
        return func(*args, **kwargs)
    return wrapper
