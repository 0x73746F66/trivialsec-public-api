from os import getenv
from app import app

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=getenv('FLASK_RUN_PORT', default=8080))
