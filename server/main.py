#Aleksey Kaptur work


from . import app
from flask import redirect, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from . import bcrypt
from wtforms.validators import DataRequired, Length
from . import db
from flask_login import UserMixin, login_user, logout_user, login_required, LoginManager, current_user
from datetime import datetime
import os
from dotenv import load_dotenv
from flask import render_template, request, abort
from twilio.jwt.access_token import AccessToken
from twilio.jwt.access_token.grants import VideoGrant, ChatGrant
from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException


load_dotenv()
twilio_account_sid = os.environ.get('TWILIO_ACCOUNT_SID')
twilio_api_key_sid = os.environ.get('TWILIO_API_KEY_SID')
twilio_api_key_secret = os.environ.get('TWILIO_API_KEY_SECRET')
twilio_client = Client(twilio_api_key_sid, twilio_api_key_secret, twilio_account_sid)


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
    username = db.Column(db.String(100), nullable=False, default="Anonimus")
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)


class Datauser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(200), nullable=False, default="Нету описания")
    name = db.Column(db.String(100), nullable=False, default="Неуказано имя")


db.create_all()


def get_chatroom(name):
    for conversation in twilio_client.conversations.conversations.stream():
        if conversation.friendly_name == name:
            return conversation

    # a conversation with the given name does not exist ==> create a new one
    return twilio_client.conversations.conversations.create(
        friendly_name=name)


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


@app.route('/strget', methods=['POST'])
def serverstream():
    username = request.get_json(force=True).get('username')
    if not username:
        abort(401)

    conversation = get_chatroom('My Room')
    try:
        conversation.participants.create(identity=username)
    except TwilioRestException as exc:
        # do not error if the user is already in the conversation
        if exc.status != 409:
            raise

    token = AccessToken(twilio_account_sid, twilio_api_key_sid,
                        twilio_api_key_secret, identity=username)
    token.add_grant(VideoGrant(room='My Room'))
    token.add_grant(ChatGrant(service_sid=conversation.chat_service_sid))

    return {'token': token.to_jwt().decode(),
            'conversation_sid': conversation.sid}


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
    message = Message.query.order_by(Message.date_posted.desc()).all()
    return render_template('social.html', message=message)


@app.route('/addpost', methods=['GET', 'POST'])
@login_required
def addpost():
    man = User.query.get(current_user.id)
    if request.method == 'POST':
        if request.method == 'POST':
            title = request.form['title']
            content = request.form['content']
            message = Message(title=title, content=content, username=man.username)
            db.session.add(message)
            db.session.commit()
            return redirect('/social')
    return render_template('addpost.html', man=man)


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
def signin():
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
    datauser = Datauser.query.get(id)
    return render_template('dashboard.html', base=base, datauser=datauser)


@app.route('/user/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit(id):
    datauser = Datauser.query.get(id)
    base = User.query.get(id)
    if request.method == 'POST':
        datauser.name = request.form['name']
        datauser.description = request.form['description']
        db.session.commit()
        return redirect('/user/' + str(id))
    return render_template('edit.html', datauser=datauser, base=base)


@app.route('/user/<int:id>/add', methods=['GET', 'POST'])
@login_required
def add(id):
    datauser = Datauser.query.get(id)
    base = User.query.get(id)
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        datauser = Datauser(name=name, description=description)
        db.session.add(datauser)
        db.session.commit()
        return redirect('/user/' + str(id))
    return render_template('add.html', datauser=datauser, base=base)


@app.route('/profile/<int:id>')
@login_required
def profile(id):
    base = User.query.get(id)
    datauser = Datauser.query.get(id)
    return render_template('profile.html', base=base, datauser=datauser)



