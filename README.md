# prepare

- pip install -r requirements.txt

or 

- pip install flask flask-api flask-jwt-extended flask-socketio requests cryptography

# running

$ flask run

or

$ FLASK_DEBUG=1 flask run

# production

1. generate crypto key
```
    $ python
    >>> from cryptography.fernet import Fernet
    >>> Fernet.generate_key()
    b'LLwA2wV9aezIRE04qExXd5dFAfXPQF-Egc-oI9ApNYs='
```
