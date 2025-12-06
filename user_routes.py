from flask import Blueprint, render_template
from flask_login import login_required
from models import Jemaat

user_bp = Blueprint('user', __name__)

@user_bp.route('/user/dashboard')
@login_required
def user_dashboard():
    return render_template('user/user_dashboard.html')

@user_bp.route('/user/jemaat')
@login_required
def jemaat_list_user():
    jemaats = Jemaat.query.all()
    return render_template('user/jemaat_list.html', jemaats=jemaats)
