import os
import requests
import json
import uuid
from base64 import b64encode
from cryptography.fernet import Fernet
from flask import request
from flask_api import FlaskAPI, status
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, jwt_required, jwt_refresh_token_required,
    create_access_token, create_refresh_token, get_jwt_identity
)
from flask_socketio import SocketIO, send, emit, join_room, leave_room
from redis import Redis

app = FlaskAPI(__name__)

app.config['JIRA_URL'] = os.getenv('JIRA_URL', 'http://localhost:8080')
app.config['JIRA_TIMEOUT'] = os.getenv('JIRA_TIMEOUT', 5)
app.config['API_PREFIX'] = '/api/v1'
app.config['REDIS_HOST'] = os.getenv('REDIS_HOST', 'localhost')
app.config['REDIS_PORT'] = os.getenv('REDIS_PORT', 6379)
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY').encode()
app.config['CRYPTO_SECRET_KEY'] = os.getenv('CRYPTO_SECRET_KEY').encode() or Fernet.generate_key()
app.config['CORS_ORIGINS'] = os.getenv('CORS_ORIGINS')
app.config['CORS_ORIGINS_WEBSOCKET'] = os.getenv('CORS_ORIGINS_WEBSOCKET')

CORS(app, resources={r"/*": {"origins": app.config['CORS_ORIGINS']}})
socketio = SocketIO(app, cors_allowed_origins=app.config['CORS_ORIGINS_WEBSOCKET'])

redis = Redis(host=app.config['REDIS_HOST'], port=app.config['REDIS_PORT'])
jwt = JWTManager(app)

# convenience vars for f'' templating
jira_url = app.config['JIRA_URL']
api_prefix = app.config['API_PREFIX']


def validate_json_payload(*args_d, **kw_d):
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
                    if p not in data:
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
    crypto = Fernet(app.config.get('CRYPTO_SECRET_KEY'))
    return crypto.encrypt(json.dumps(credentials).encode()).decode()


def decrypt(payload):
    crypto = Fernet(app.config.get('CRYPTO_SECRET_KEY'))
    return json.loads(crypto.decrypt(payload).decode())


def get_jira_request_headers(credentials):
    auth = b64encode('{username}:{password}'.format(**credentials).encode()).decode()
    return {'Content-Type': 'application/json', 'Authorization': f'Basic {auth}'}


def session_set(data):
    session_id = str(uuid.uuid4())
    redis.set(session_id, data)
    return session_id


def session_get(session_id):
    return redis.get(session_id)


def format_display_name(name):
    names = name.split("@")[0].split(".")
    return " ".join([name.title() for name in names])


@app.route(f'{api_prefix}/auth/login', methods=['POST'])
@validate_json_payload(required=['username', 'password'])
def login():
    credentials = request.get_json()

    if not check_credentials(credentials):
        return {
            'msg': 'bad credentials'
        }, status.HTTP_401_UNAUTHORIZED

    session_id = session_set(encrypt(credentials))
    user_claims = {
        'display_name': format_display_name(credentials['username'])
    }

    return {
        'access_token': create_access_token(identity=session_id, user_claims=user_claims),
        'refresh_token': create_refresh_token(identity=session_id)
    }, status.HTTP_200_OK


@app.route(f'{api_prefix}/auth/logout', methods=['POST'])
@jwt_required
def logout():
    redis.delete(get_jwt_identity())
    return {
      'msg': 'logged out'
    }, status.HTTP_200_OK


@app.route(f'{api_prefix}/auth/refresh', methods=['POST'])
@jwt_refresh_token_required
def refresh():
    return {
        'access_token': create_access_token(identity=get_jwt_identity()),
        'refresh_token': create_refresh_token(identity=get_jwt_identity())
    }, status.HTTP_200_OK


@app.route(f'{api_prefix}/<path:path>', methods=['GET', 'POST'])
@jwt_required
def jira_api(path):
    url = f'{jira_url}/rest/agile/1.0/{path}'
    session_data = session_get(get_jwt_identity())
    headers = get_jira_request_headers(decrypt(session_data))
    try:
        return requests.get(url, params=request.args, headers=headers).json()
    except Exception as e:
        return {
            'msg': f'upstream error - {e}'
        }, status.HTTP_503_SERVICE_UNAVAILABLE


@socketio.on('join')
def on_join(data):
    user = data['user']
    room = data['room']
    join_room(room)
    send(user + ' has entered the room.', room=room)


@socketio.on('leave')
def on_leave(data):
    user = data['user']
    room = data['room']
    leave_room(room)
    send(user + ' has left the room.', room=room)


if __name__ == "__main__":
    socketio.run(app)
