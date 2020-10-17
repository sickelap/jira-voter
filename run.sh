#!/bin/sh

# key must be 32 url-safe base64-encoded bytes.
# Generate with Fernet.generate_key()
export CRYPTO_SECRET_KEY=pWLpAIl_Vca9-fJ1xn2hv-maigRv4K8h1O1HBLA_DpQ=

export JWT_SECRET_KEY=1sWCYYQHnt5RV6e5jI4ptVewxhCypxST

export CORS_ORIGINS="*"
export CORS_ORIGINS_WEBSOCKET="*"

export FLASK_DEBUG=1

flask run
