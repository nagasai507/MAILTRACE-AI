from flask import Flask
from flask_cors import CORS
from .extensions import db,jwt
from .config import Config

def create_app():
    app=Flask(__name__); app.config.from_object(Config)
    CORS(app,resources={r'/api/*':{'origins':app.config['CORS_ORIGINS'].split(',')}})
    db.init_app(app); jwt.init_app(app)
    from . import models
    with app.app_context(): db.create_all()
    from .routes import api; app.register_blueprint(api,url_prefix='/api')
    return app
