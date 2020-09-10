from flask import (
    abort,
    current_app as app,
    g,
    jsonify,
    request,
    Blueprint
)
from marshmallow import ValidationError

from ca.serialization import IssueCertificateRequest

router = Blueprint('router', __name__)

@router.route('/milena-svilena')
def health_check():
    return {'status': 'OK'}

@router.route('/certificates/issue', methods=['POST'])
# @oidc.accept_token(True, ['profile', 'email'])
# @protected
def issue_cert():
    json_data = request.get_json()
    cert_request = IssueCertificateRequest()
    if not json_data:
        return jsonify({'message': 'No input data provided'}), 400
    try:
        req = cert_request.load(data=json_data)
    except ValidationError as err:
        return jsonify(err.messages), 422

    # return issue_certificate(req.data)
