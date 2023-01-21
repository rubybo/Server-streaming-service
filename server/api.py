from flask import Flask
from flask_restful import Api, Resourse


app = Flask(__name__)
api = Api()


class Main(Resourse):
    def get(self):
        return {"message": "Hello World!"}


api.add_resource(Main, "/api/hw")
api.init_app(app)


if __name__ == '__main__':
    app.run()