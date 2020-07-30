import os
import requests
import json
from base64 import b64encode
from cryptography.fernet import Fernet
from flask import request, url_for
from flask_api import FlaskAPI, status, exceptions
from flask_jwt_extended import (
    JWTManager, jwt_required, jwt_refresh_token_required,
    create_access_token, create_refresh_token, get_jwt_identity
)

app = FlaskAPI(__name__)

app.config['JIRA_URL'] = os.getenv('JIRA_URL', 'http://localhost:8080')
app.config['JIRA_TIMEOUT'] = os.getenv('JIRA_TIMEOUT', 5)
app.config['CRYPTO_SECRET_KEY'] = b'SqGSpFVxQyzQAizbGasl1sxhsKPr3r-LRDtQrULhuQo=' # Fernet.generate_key()
app.config['JWT_SECRET_KEY'] = b'\xc5\xb1\xe6`N\xd2\xfe\xb7\xef\xa2O\xc7~\xf3\xb3\x1b\x13PC\xbe\xefm\xc4\xe0\xf5\x8e\n\xaa\xbf\xbc\xc7\xb9' # os.urandom(32)
app.config['API_PREFIX'] = '/api/v1'

jwt = JWTManager(app)


# convenience vars for f'' templating
jira_url = app.config['JIRA_URL']
api_prefix = app.config['API_PREFIX']


def validate_json(*args_d, **kw_d):
    def wrap(f):
        def wrapper(*args, **kw):
            try:
                data = request.get_json()
            except Exception as e:
                return {
                    'msg': 'payload must be a valid json' + str(e)
                }, status.HTTP_400_BAD_REQUEST

            if 'required' in kw_d:
                for p in kw_d['required']:
                    if not p in data:
                        return {
                            'msg': 'missing property: {}'.format(p)
                        }, status.HTTP_400_BAD_REQUEST
            return f(*args, **kw)
        return wrapper
    return wrap


def check_credentials(credentials):
    try:
        url = f'{jira_url}/rest/agile/1.0/board?maxResults=1'
        headers = get_jira_request_headers(credentials)
        return requests.get(url, headers=headers, timeout=app.config['JIRA_TIMEOUT']).ok
    except Exception:
        return False


def encrypt(credentials):
    fernet = Fernet(app.config.get('CRYPTO_SECRET_KEY'))
    return fernet.encrypt(json.dumps(credentials).encode()).decode()


def decrypt(payload):
    fernet = Fernet(app.config.get('CRYPTO_SECRET_KEY'))
    return json.loads(fernet.decrypt(payload.encode()).decode())


def get_jira_request_headers(credentials):
    auth = b64encode('{username}:{password}'.format(**credentials).encode()).decode()
    return {'Content-Type': 'application/json', 'Authorization': f'Basic {auth}'}


@app.route('/api/v1/auth/login', methods=['POST'])
@validate_json(required=['username', 'password'])
def login():
    credentials = request.get_json()

    if not check_credentials(credentials):
        return {
            'msg': 'bad credentials'
        }, status.HTTP_401_UNAUTHORIZED

    encrypted_credentials = encrypt(credentials)

    return {
        'access_token': create_access_token(identity=encrypted_credentials),
        'refresh_token': create_refresh_token(identity=encrypted_credentials)
    }, status.HTTP_200_OK


@app.route('/api/v1/auth/refresh', methods=['POST'])
@jwt_refresh_token_required
def regresh():
    return {
        'access_token': create_access_token(identity=get_jwt_identity())
    }, status.HTTP_200_OK


@app.route(f'{api_prefix}/<path:path>', methods=['GET','PUT','POST'])
@jwt_required
def jira_api_get(path):
    url = f'{jira_url}/rest/agile/1.0/{path}'
    headers = get_jira_request_headers(decrypt(get_jwt_identity()))
    try:
        return requests.get(url, params=request.args, headers=headers).json()
    except Exception as e:
        return {
            'msg': f'upstream error - {e}'
        }, status.HTTP_503_SERVICE_UNAVAILABLE


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
