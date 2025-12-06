from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from flask_login import login_required, current_user
from models import Jemaat, db


staff_bp = Blueprint('staff', __name__)

@staff_bp.route('/staff/dashboard')
@login_required
def staff_dashboard():
    return render_template('staff/staff_dashboard.html')

from forms import JemaatForm

@staff_bp.route('/staff/jemaat/add', methods=['GET', 'POST'])
@login_required
def jemaat_add():
    form = JemaatForm()
    if form.validate_on_submit():
        jemaat = Jemaat(
            nama=form.nama.data,
            tanggal_lahir=form.tanggal_lahir.data,
            jenis_kelamin=form.jenis_kelamin.data,
            alamat=form.alamat.data,
            no_hp=form.no_hp.data
        )
        db.session.add(jemaat)
        try:
            db.session.commit()
            flash('Data jemaat berhasil ditambahkan.', 'success')
            # Log aktivitas penambahan data
            current_app.logger.info(f"User '{current_user.username}' (ID: {current_user.id}) menambahkan jemaat baru: '{jemaat.nama}' (ID: {jemaat.id}).")
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Gagal menambahkan jemaat: {e}")
            flash("Terjadi kesalahan saat menambahkan data jemaat.", "danger")
        return redirect(url_for('staff.jemaat_list'))
    return render_template('staff/jemaat_add.html', form=form)

@staff_bp.route('/staff/jemaat/list')
@login_required
def jemaat_list():
    jemaats = Jemaat.query.all()
    return render_template('staff/jemaat_list.html', jemaats=jemaats)

@staff_bp.route('/staff/jemaat/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def jemaat_edit(id):
    jemaat = Jemaat.query.get_or_404(id)
    form = JemaatForm(obj=jemaat) # Pre-populate form with existing data
    if form.validate_on_submit():
        jemaat.nama = form.nama.data
        jemaat.tanggal_lahir = form.tanggal_lahir.data
        jemaat.jenis_kelamin = form.jenis_kelamin.data
        jemaat.alamat = form.alamat.data
        jemaat.no_hp = form.no_hp.data
        try:
            db.session.commit()
            flash("Data jemaat berhasil diperbarui.", "success")
            # Log aktivitas pembaruan data
            current_app.logger.info(f"User '{current_user.username}' (ID: {current_user.id}) memperbarui data jemaat: '{jemaat.nama}' (ID: {jemaat.id}).")
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Gagal memperbarui jemaat (ID: {id}): {e}")
            flash("Terjadi kesalahan saat memperbarui data jemaat.", "danger")
        return redirect(url_for('staff.jemaat_list'))
    return render_template('staff/jemaat_edit.html', form=form, jemaat=jemaat)

@staff_bp.route('/staff/jemaat/delete/<int:id>', methods=['POST'])
@login_required
def jemaat_delete(id):
    jemaat = Jemaat.query.get_or_404(id)
    try:
        jemaat_nama = jemaat.nama # Simpan nama sebelum dihapus untuk logging
        db.session.delete(jemaat)
        db.session.commit()
        flash("Data jemaat berhasil dihapus.", "success")
        # Log aktivitas penghapusan data
        current_app.logger.info(f"User '{current_user.username}' (ID: {current_user.id}) menghapus jemaat: '{jemaat_nama}' (ID: {id}).")
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Gagal menghapus jemaat (ID: {id}): {e}")
        flash("Terjadi kesalahan saat menghapus data jemaat.", "danger")
    return redirect(url_for('staff.jemaat_list'))