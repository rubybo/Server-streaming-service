from server import app
from server import db


if __name__ == '__main__':
    db.create_all()
    app.run()