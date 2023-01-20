from . import app
from flask import render_template


@app.route('/')
@app.route('/home')
def index():
    return render_template('index.html')


@app.route('/stream')
def stream():
    return render_template('stream.html')


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404