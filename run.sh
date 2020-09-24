#!/bin/sh

export FLASK_DEBUG=1

export JWT_SECRET_KEY=1sWCYYQHnt5RV6e5jI4ptVewxhCypxST

# key must be 32 url-safe base64-encoded bytes.
# Generate with Fernet.generate_key()
export CRYPTO_SECRET_KEY=pWLpAIl_Vca9-fJ1xn2hv-maigRv4K8h1O1HBLA_DpQ=

``flask run
