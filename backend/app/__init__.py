import logging
import os
from flask import Flask, jsonify
from flask_cors import CORS
from .extensions import db, jwt, migrate
from .config import Config
from .security import apply_security_headers


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    logging.basicConfig(
        level=logging.INFO if not app.config['IS_PRODUCTION'] else logging.WARNING,
        format='%(asctime)s %(levelname)s %(name)s: %(message)s',
    )

    # Explicit origins + methods + headers rather than a blanket '*':
    # credentials-bearing requests must not be paired with a wildcard
    # origin, and enumerating allowed methods/headers narrows what a
    # malicious page on another origin could even attempt.
    origins = [o.strip() for o in app.config['CORS_ORIGINS'].split(',') if o.strip()]
    CORS(app, resources={r'/api/*': {'origins': origins}},
         methods=['GET', 'POST', 'OPTIONS'],
         allow_headers=['Content-Type', 'Authorization'],
         max_age=600)

    db.init_app(app)
    jwt.init_app(app)
    migrate.init_app(app, db)

    # Models must be imported (registering their tables with SQLAlchemy's
    # metadata) before create_all() runs, or a fresh DB raises
    # "no such table" on first request. Keep this ordering.
    with app.app_context():
        from . import models  # noqa: F401
        if not app.config['IS_PRODUCTION']:
            db.create_all()

        admin_email = os.getenv('SEED_ADMIN_EMAIL')
        admin_password = os.getenv('SEED_ADMIN_PASSWORD')
        if admin_email and admin_password:
            # Local bootstrapping often sets these values before the app is
            # launched; if they are present, the app should self-seed the
            # admin user so the default login works without an extra manual
            # script invocation.
            from seed import ensure_admin_user
            ensure_admin_user(admin_email, admin_password)

    from .routes import api
    app.register_blueprint(api, url_prefix='/api')

    @app.after_request
    def _headers(resp):
        return apply_security_headers(resp)

    @app.errorhandler(413)
    def _too_large(e):
        return jsonify(error='Upload exceeds the maximum allowed size.'), 413

    @app.errorhandler(429)
    def _rate_limited(e):
        return jsonify(error='Too many requests. Please slow down.'), 429

    @app.errorhandler(500)
    def _server_error(e):
        app.logger.exception('Unhandled server error')
        # Never leak stack traces / internals to the client.
        return jsonify(error='An internal error occurred.'), 500

    return app
