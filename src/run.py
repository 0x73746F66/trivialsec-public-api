from os import getenv
from app import create_app

if __name__ == '__main__':
    create_app().run(host='0.0.0.0', port=getenv('FLASK_RUN_PORT', default=5000))
