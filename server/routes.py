#Aleksey Kaptur work


from . import app
from flask import render_template


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
    return render_template('register.html')