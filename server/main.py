#Aleksey Kaptur work


from . import app
from flask import render_template, request, redirect
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from . import bcrypt
from wtforms.validators import DataRequired, Length
from . import db
from flask_login import UserMixin
from datetime import datetime


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)


db.create_all()



class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=25)], render_kw={"placeholder": "Имя пользователя", "class":"form-control"})
    password = PasswordField('Password', validators=[DataRequired(), Length(min=3, max=25)], render_kw={"placeholder": "Пароль", "class": "form-control"})
    submit = SubmitField('Зарегистрироваться', render_kw={"class": "btn btn-primary"})


@app.get('/')
@app.get('/home')
def index():
    return render_template('index.html')


@app.route('/stream', methods=['GET', 'POST'])
def stream():
    return render_template('stream.html')


@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('error.html'), 500


@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html'), 403


@app.get('/about')
def about():
    return render_template('about.html')


@app.route('/social', methods=['GET', 'POST'])
def social():
    return render_template('social.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=username, password=password)
        db.session.add(user)
        db.session.commit()
        return redirect('/')
    return render_template('register.html', form=form)

