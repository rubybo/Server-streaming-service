#Aleksey Kaptur work


from . import app
from flask import render_template, request, redirect, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from . import bcrypt
from wtforms.validators import DataRequired, Length
from . import db
from flask_login import UserMixin, login_user, logout_user, login_required, LoginManager
from datetime import datetime


login_manager = LoginManager(app)


login_manager.login_view = "login"


login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


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


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=25)], render_kw={"placeholder": "Имя пользователя", "class":"form-control"})
    password = PasswordField('Password', validators=[DataRequired(), Length(min=3, max=25)], render_kw={"placeholder": "Пароль", "class": "form-control"})
    submit = SubmitField('Войти', render_kw={"class": "btn btn-primary"})


@app.get('/')
@app.get('/home')
def index():
    return render_template('index.html')


@app.route('/stream', methods=['GET', 'POST'])
@login_required
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
@login_required
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
        return redirect('/login')
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect('/user/' + str(user.id))
        else:
            flash('Неправильный логин или пароль')

    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect('/home')


@app.route('/user/<int:id>')
@login_required
def data(id):
    base = User.query.get(id)
    return render_template('dashboard.html', base=base)





