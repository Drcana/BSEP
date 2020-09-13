import base64
import datetime
from io import BytesIO
from typing import Mapping

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import (
    ReasonFlags,
    load_pem_x509_certificate,
    ocsp,
    Certificate
)
from flask import current_app as app
from sqlalchemy.orm.exc import NoResultFound

from ca.models import Record

REASON_FLAGS = {
    'Unspecified': ReasonFlags.unspecified,
    'KeyCompromise': ReasonFlags.key_compromise,
    'CACompromise': ReasonFlags.ca_compromise,
    'AffiliationChanged': ReasonFlags.affiliation_changed,
    'Superseded': ReasonFlags.superseded,
    'CessationOfOperation': ReasonFlags.cessation_of_operation,
    'CertificateHold': ReasonFlags.certificate_hold,
    'PrivilegeWithdrawn': ReasonFlags.privilege_withdrawn,
    'AACompromise': ReasonFlags.aa_compromise,
    'RemoveFromCRL': ReasonFlags.remove_from_crl
}

def cert_status_response(req):
    ocsp_req = ocsp.load_der_ocsp_request(req)

    try:
        sn = str(ocsp_req.serial_number)
        record = Record.query.filter_by(sn=sn).one()

        if record.revoked_at:
            status = ocsp.OCSPCertStatus.REVOKED
            revocation_time = record.revoked_at
            if record.reason:
                revocation_reason = REASON_FLAGS[record.reason]
            else:
                revocation_reason = ReasonFlags.unspecified
        else:
            status = ocsp.OCSPCertStatus.GOOD
            revocation_time, revocation_reason = None, None


    except NoResultFound:
        raise RuntimeError('Unknown certificate.')

    cert: Certificate = load_pem_x509_certificate(
        data=record.cert,
        backend=default_backend()
    )

    issuer = app.config['ISSUERS'][record.issuer_sn]
    responder_cert = app.config['CERT']
    responder_key = app.config['KEY']

    builder = ocsp.OCSPResponseBuilder()
    builder = builder.add_response(
        cert=cert,
        issuer=issuer,
        algorithm=ocsp_req.hash_algorithm,
        cert_status=status,
        this_update=datetime.datetime.now(),
        next_update=None,
        revocation_time=revocation_time,
        revocation_reason=revocation_reason
    ).responder_id(
        ocsp.OCSPResponderEncoding.HASH, responder_cert
    )

    response = builder.sign(responder_key, hashes.SHA256())
    return response.public_bytes(serialization.Encoding.DER)

def save_cert(data, issuer):
    payload: Mapping = jwt.decode(
        jwt=data,
        key=issuer.public_key(),
        algorithms=['ES256', 'ES512']
    )
    print(issuer)
    if 'certificate' not in payload.keys() or 'issuerSer' not in payload:
        raise RuntimeError('Unprocessable token.')

    cert_bytes = base64.b64decode(
        bytes(payload['certificate'], encoding='utf-8')
    )
    cert_stream = BytesIO(cert_bytes)
    cert: Certificate = load_pem_x509_certificate(
        data=cert_stream.read(),
        backend=default_backend()
    )

    sn = str(cert.serial_number)
    issuer_sn = str(payload['issuerSer'])

    try:
        Record.query.filter_by(sn=sn).one()
        raise RuntimeError()
    except NoResultFound:
        pass

    record = Record()
    record.sn = str(cert.serial_number)
    record.cert = cert_stream.getvalue()
    record.issuer_sn = issuer_sn
    record.created_at = datetime.datetime.now()
    record.revoked_at = None
    record.save()

    return sn