from flask import (
    abort,
    current_app as app,
    g,
    jsonify,
    request,
    Blueprint
)
from marshmallow import ValidationError
from sqlalchemy.orm.exc import NoResultFound

from ca.serialization import IssueCertificateRequest
from ca.services import issue_certificate, get_certificate_by_pk, list_certificates, revoke_certificate

router = Blueprint('router', __name__)

@router.route('/')
def home():
    return {'status':'home'}

@router.route('/certificates/issue', methods=['POST'])
def issue_cert():
    json_data = request.get_json()
    cert_request = IssueCertificateRequest()
    if not json_data:
        return jsonify({'message': 'No input data provided'}), 400
    try:
        req = cert_request.load(data=json_data)
    except ValidationError as err:
        return jsonify(err.messages), 422
    return issue_certificate(req)

@router.route('/certificates/<string:pk>', methods=['GET'])
def get_cert(pk):
    try:
        return get_certificate_by_pk(pk)
    except NoResultFound:
        abort(404)

@router.route('/certificates', methods=['GET'])
def list_certs():
    return list_certificates()

@router.route('/certificates/revoke/<string:pk>', methods=['POST'])
# @oidc.accept_token(True, ['profile', 'email'])
# @protected
def revoke_cert(pk):
    try:
        revoke_certificate(pk)
        return "OK", 200
    except NoResultFound:
        abort(404)
