from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, SubmitField, DateField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, Regexp, EqualTo, ValidationError
from models import User

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(message="Username harus diisi."),
        Length(min=3, max=20),
        Regexp('^[a-zA-Z0-9_.-]+$', message='Username hanya boleh berisi huruf, angka, titik, underscore, atau strip.')
    ])
    email = StringField('Email', validators=[
        DataRequired(message="Email harus diisi."),
        Email(message="Format email tidak valid.")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message="Password harus diisi."),
        Length(min=6, message="Password minimal 6 karakter.")
    ])
    confirm_password = PasswordField('Konfirmasi Password', validators=[
        DataRequired(message="Konfirmasi password harus diisi."),
        EqualTo('password', message='Password tidak cocok.')
    ])
    role = SelectField('Role', choices=[('user', 'User'), ('staff', 'Staff'), ('admin', 'Admin')], validators=[DataRequired()])
    submit = SubmitField('Register')

    def validate_username(self, username):
        if User.query.filter_by(username=username.data).first():
            raise ValidationError('Username sudah digunakan!')

    def validate_email(self, email):
        if User.query.filter_by(email=email.data).first():
            raise ValidationError('Email sudah terdaftar!')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(message="Username harus diisi.")])
    password = PasswordField('Password', validators=[DataRequired(message="Password harus diisi.")])
    submit = SubmitField('Login')

class JemaatForm(FlaskForm):
    nama = StringField('Nama Jemaat', validators=[
        DataRequired(message="Nama jemaat harus diisi.")
    ])
    tanggal_lahir = DateField('Tanggal Lahir', format='%Y-%m-%d', validators=[DataRequired(message="Tanggal lahir harus diisi.")])
    jenis_kelamin = SelectField('Jenis Kelamin', choices=[
        ('Laki-laki', 'Laki-laki'),
        ('Perempuan', 'Perempuan')
    ], validators=[DataRequired(message="Jenis kelamin harus dipilih.")])
    alamat = TextAreaField('Alamat')
    no_hp = StringField('No HP', validators=[
        Regexp(r'^[0-9+\- ]{6,20}$', message="Format nomor HP tidak valid.")
    ])
    submit = SubmitField('Simpan')