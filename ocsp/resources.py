import base64
from io import BytesIO

from flask import (

    jsonify,
    send_file,
    request,
    Blueprint
)

from ocsp.helpers import cert_status_response, save_cert, revoke_certificate

import json
import logging
import urllib.parse
from functools import wraps
from io import BytesIO

import jwt

from cryptography.hazmat.backends import default_backend
from cryptography.x509 import (
    load_pem_x509_certificate,
    Certificate, NameOID, Name
)
from flask import (
    current_app as app,
    request
)


router = Blueprint('router', __name__)


class Error(RuntimeError):

    def __init__(self, code, msg, level):
        self.code = code
        self.level = level
        super().__init__(msg)


def extract_issuer():
    issuer_pem = urllib.parse.unquote(request.headers['X-SSL-CERT'])
    issuer_bytes = BytesIO(bytes(issuer_pem, encoding='utf-8'))
    read_bytes = issuer_bytes.read()
    read_bytes = read_bytes.decode("utf-8").replace('\\n', '\n').encode();
    issuer: Certificate = load_pem_x509_certificate(
        data=read_bytes,
        backend=default_backend()
    )

    return issuer

def requires_issuer(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if 'X-SSL-CERT' not in request.headers:
             return '', 403

        kwargs['issuer'] = extract_issuer()
        try:
            return func(*args, **kwargs)

        except jwt.exceptions.InvalidSignatureError:
            raise Error(403, 'Invalid signature', logging.WARNING)
        except jwt.exceptions.InvalidTokenError:
            raise Error(400, 'Invalid token', logging.INFO)
        except RuntimeError as e:
            raise Error(400, str(e), logging.INFO)

    return wrapper



@router.route('/admin/certificates/save', methods=['POST'])
@requires_issuer
def save_certificate(**kwargs):
    issuer = kwargs['issuer']
    sn = save_cert(request.get_data(), issuer);
    return { 'message': 'certificate registered successfully'}



@router.route('/admin/certificates/revoke', methods=['POST'])
@requires_issuer
def revoke_cert(**kwargs):
    issuer = kwargs['issuer']
    revoke_certificate(request.get_data(), issuer)
    return 'OK'


@router.route('/certificates', methods=['POST'], defaults={'data': None})
@router.route('/certificates/<string:data>', methods=['GET'])
def cert_status(data, **kwargs):
    if request.method == 'POST':
        req = request.get_data()
    else:
        req = base64.urlsafe_b64decode(data)
    resp = cert_status_response(req)
    return send_file(BytesIO(resp), mimetype='application/ocsp-response')

@router.route('/')
def test():
    return jsonify({'test': 'OK'})
