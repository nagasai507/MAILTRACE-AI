import os
from app import create_app

app = create_app()

if __name__ == '__main__':
    debug = os.getenv('FLASK_ENV', 'development') != 'production'
    # debug=True enables the Werkzeug interactive debugger, which can
    # execute arbitrary code from the browser if ever exposed beyond
    # localhost — never turn it on outside local development.
    app.run(host='localhost', port=int(os.getenv('PORT', '5001')), debug=debug)
