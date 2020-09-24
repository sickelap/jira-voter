FROM tiangolo/uwsgi-nginx-flask:python3.8-alpine
RUN apk add --update gcc python3-dev musl-dev libffi-dev openssl-dev
RUN pip install flask flask-api flask-jwt-extended flask-socketio flask-cors requests cryptography redis
COPY ./app /app
