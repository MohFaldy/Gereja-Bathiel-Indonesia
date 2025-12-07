from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from flask_login import login_required, current_user
from models import User, Jemaat, db, bcrypt
from utils import sanitize_input, admin_exists
from forms import JemaatForm, AdminAddUserForm
import re

admin_bp = Blueprint('admin', __name__)
VALID_ROLES = ["admin", "staff", "user"]
USERNAME_PATTERN = r'^[a-zA-Z0-9_.-]{3,20}$'
PHONE_PATTERN = r'^[0-9+\- ]{6,20}$'


# =====================================================
#                DASHBOARD ADMIN
# =====================================================
@admin_bp.route('/admin/dashboard')
@login_required
def admin_dashboard():
    return render_template('admin/admin_dashboard.html')


# =====================================================
#              KELOLA USER
# =====================================================
@admin_bp.route('/admin/users')
@login_required
def manage_users():
    form = AdminAddUserForm()
    users = User.query.all()
    return render_template('admin/user_management.html', users=users, form=form)


@admin_bp.route('/admin/users/add', methods=['POST'])
@login_required
def add_user():
    form = AdminAddUserForm()
    if form.validate_on_submit():
        role = form.role.data
        if role == "admin" and admin_exists():
            flash("Admin hanya boleh satu!", "danger")
        else:
            hashed_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            new_user = User(
                username=form.username.data,
                email=form.email.data,
                password=hashed_pw,
                role=role,
                is_verified=True  # User yang dibuat admin langsung terverifikasi
            )
            db.session.add(new_user)
            try:
                db.session.commit()
                flash("User baru berhasil ditambahkan!", "success")
                current_app.logger.info(f"Admin '{current_user.username}' menambahkan user baru: '{new_user.username}'.")
            except Exception as e:
                db.session.rollback()
                current_app.logger.error(f"Admin '{current_user.username}' gagal menambahkan user: {e}")
                flash("Terjadi kesalahan saat menambahkan user.", "danger")
    else:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"{getattr(form, field).label.text}: {error}", "danger")

    return redirect(url_for('admin.manage_users'))


@admin_bp.route('/admin/users/delete/<int:id>', methods=['POST']) # Tambahkan methods=['POST'] untuk keamanan
@login_required
def delete_user(id):

    user = User.query.get(id)

    if not user:
        flash("User tidak ditemukan.", "danger")
        return redirect(url_for('admin.manage_users'))

    # ❗ Cegah hapus admin satu-satunya
    if user.role == "admin" and User.query.filter_by(role="admin").count() == 1:
        flash("Tidak bisa menghapus admin satu-satunya!", "danger")
        return redirect(url_for('admin.manage_users'))

    try:
        deleted_username = user.username
        deleted_user_id = user.id
        db.session.delete(user)
        db.session.commit()
        flash("User berhasil dihapus.", "success")
        # Log aktivitas
        current_app.logger.info(f"Admin '{current_user.username}' (ID: {current_user.id}) menghapus user: '{deleted_username}' (ID: {deleted_user_id}).")
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Admin '{current_user.username}' gagal menghapus user (ID: {id}): {e}")
        flash("Terjadi kesalahan saat menghapus user.", "danger")
    return redirect(url_for('admin.manage_users'))


# =====================================================
#              KELOLA ROLE USER
# =====================================================
@admin_bp.route('/admin/roles', methods=['GET', 'POST'])
@login_required
def manage_roles():


    if request.method == "POST":

        user_id = sanitize_input(request.form.get('user_id'))
        new_role = sanitize_input(request.form.get('role'))



        user = User.query.get(user_id)
        if not user or new_role not in VALID_ROLES:
            flash("User atau Role tidak valid!", "danger")
        elif user.role == "admin" and new_role != "admin" and User.query.filter_by(role="admin").count() == 1:
            flash("Tidak bisa mengubah role admin satu-satunya!", "danger")
        elif new_role == "admin" and user.role != "admin" and admin_exists():
            flash("Hanya boleh ada satu admin!", "danger")
        else:
            user.role = new_role
            try:
                db.session.commit()
                flash("Role berhasil diperbarui!", "success")
                current_app.logger.info(f"Admin '{current_user.username}' mengubah role user '{user.username}' menjadi '{new_role}'.")
            except Exception as e:
                db.session.rollback()
                current_app.logger.error(f"Admin '{current_user.username}' gagal memperbarui role untuk user (ID: {user_id}): {e}")
                flash("Terjadi kesalahan saat memperbarui role.", "danger")
        return redirect(url_for('admin.manage_roles'))

    users = User.query.all()

    return render_template('admin/role_management.html', users=users)


# =====================================================
#              KELOLA DATA JEMAAT
# =====================================================
@admin_bp.route('/admin/jemaat')
@login_required
def manage_jemaat():
    # Siapkan form kosong untuk modal 'Add Jemaat'
    form = JemaatForm()
    jemaats = Jemaat.query.order_by(Jemaat.id.desc()).all()
    return render_template('admin/jemaat_management.html', jemaats=jemaats, form=form)


@admin_bp.route('/admin/jemaat/add', methods=['POST'])
@login_required
def add_jemaat():
    form = JemaatForm()
    if form.validate_on_submit():
        jemaat = Jemaat(
            nama=form.nama.data,
            tanggal_lahir=form.tanggal_lahir.data,
            jenis_kelamin=form.jenis_kelamin.data,
            alamat=form.alamat.data,
            no_hp=form.no_hp.data
        )
        try:
            db.session.add(jemaat)
            db.session.commit()
            flash("Jemaat baru berhasil ditambahkan!", "success")
            # Log aktivitas
            current_app.logger.info(f"Admin '{current_user.username}' (ID: {current_user.id}) menambahkan jemaat baru: '{jemaat.nama}' (ID: {jemaat.id}).")
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Admin '{current_user.username}' gagal menambahkan jemaat: {e}")
            flash("Terjadi kesalahan saat menambahkan jemaat.", "danger")
        return redirect(url_for('admin.manage_jemaat'))
    
    # Jika validasi gagal, render ulang halaman dengan error
    jemaats = Jemaat.query.order_by(Jemaat.id.desc()).all()
    flash("Gagal menambahkan jemaat. Periksa kembali data yang Anda masukkan.", "danger")
    return render_template('admin/jemaat_management.html', jemaats=jemaats, form=form)


@admin_bp.route('/admin/jemaat/update/<int:id>', methods=['POST'])
@login_required
def update_jemaat(id):
    jemaat = Jemaat.query.get_or_404(id)
    form = JemaatForm(request.form) # Ambil data dari form yang di-submit
    if form.validate():
        # Populate object jemaat dari form
        form.populate_obj(jemaat)
        try:
            db.session.commit()
            flash("Data jemaat berhasil diperbarui!", "success")
            # Log aktivitas
            current_app.logger.info(f"Admin '{current_user.username}' (ID: {current_user.id}) memperbarui data jemaat: '{jemaat.nama}' (ID: {jemaat.id}).")
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Admin '{current_user.username}' gagal memperbarui jemaat (ID: {id}): {e}")
            flash("Terjadi kesalahan saat memperbarui data jemaat.", "danger")
    else:
        # Jika validasi gagal, flash pesan error
        # Anda bisa membuat ini lebih spesifik dengan iterasi form.errors
        flash("Gagal memperbarui data. Periksa kembali input Anda.", "danger")
    return redirect(url_for('admin.manage_jemaat'))


@admin_bp.route('/admin/jemaat/delete/<int:id>', methods=['POST']) # Tambahkan methods=['POST'] untuk keamanan
@login_required
def delete_jemaat(id):

    # Tambahkan CSRF protection jika form delete adalah POST
    # if not validate_csrf_token(): # Anda perlu mengimplementasikan fungsi ini
    #    flash("Invalid CSRF token.", "danger")
    #    return redirect(url_for('admin.manage_jemaat'))
    jemaat = Jemaat.query.get(id)

    if not jemaat:
        flash("Data jemaat tidak ditemukan!", "danger")
        return redirect(url_for('admin.manage_jemaat'))

    try:
        jemaat_nama = jemaat.nama
        db.session.delete(jemaat)
        db.session.commit()
        flash("Data jemaat berhasil dihapus.", "success")
        # Log aktivitas
        current_app.logger.info(f"Admin '{current_user.username}' (ID: {current_user.id}) menghapus jemaat: '{jemaat_nama}' (ID: {id}).")
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Admin '{current_user.username}' gagal menghapus jemaat (ID: {id}): {e}")
        flash("Terjadi kesalahan saat menghapus data jemaat.", "danger")
    return redirect(url_for('admin.manage_jemaat'))
