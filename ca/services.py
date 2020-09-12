
import base64
import datetime
import os
import shutil
import tempfile
from collections import defaultdict
from io import BytesIO

import jwt
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from flask import (
    current_app as app,
    send_from_directory,
    jsonify,
)

from ca.models import Record


def issue_certificate(request):
    issuer_cert = app.config['CERT']
    issuer = issuer_cert.subject
    issuer_key = app.config['KEY']
    subject = parse_subject(request['subject'])

    subject_key, subject_pk = None, None
    if request['gen_keys']:
        subject_key, subject_pk = generate_keys()
    elif 'public_key' in request:
        key = bytes(request['public_key'], encoding='utf-8')
        stream = BytesIO(key)
        subject_key = serialization.load_pem_public_key(
            data=stream.read(),
            backend=default_backend()
        )

    key_usage = None
    if 'key_usage' in request:
        key_usage = parse_key_usage(request['key_usage'])

    ext_key_usage = None
    if 'ext_key_usage' in request:
        ext_key_usage = parse_extended_key_usage(request['ext_key_usage'])

    name_const = None
    if 'name_const' in request:
        name_const = parse_name_constraints(request['name_const'])

    sub_alt_name = None
    if 'sub_alt_name' in request:
        sub_alt_name = parse_subject_alt_name(request['sub_alt_name'])

    auth_info_access = None
    if 'auth_info_access' in request:
        auth_info_access = parse_auth_info_access(request['auth_info_access'])

    cert = generate(
        issuer,
        issuer_key,
        issuer_cert,
        subject,
        subject_key,
        key_usage,
        ext_key_usage,
        sub_alt_name,
        name_const,
        auth_info_access,
        ca=request['ca'],
    )

    ser_key_pub, ser_key = None, None
    if request['gen_keys']:
        ser_key_pub, ser_key = serialize_keys(subject_key, subject_pk)

    ser_cert = cert.public_bytes(serialization.Encoding.PEM)
    ser_certs = [ser_cert] + app.config['CERT_CHAIN']

    Record(
        cert_pk=str(cert.serial_number),
        cert=ser_cert,
        common_name=request['subject']['common']
    ).save()



    return wrap(request['subject']['common'], ser_key_pub, ser_key, ser_certs)

def parse_subject(subject):
    country = []
    if 'country' in subject:
        country.append(
            x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, subject['country'])
        )
    return x509.Name(country + [
        x509.NameAttribute(
            x509.oid.NameOID.ORGANIZATION_NAME, subject['org']
        ),
        x509.NameAttribute(
            x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME,
            subject['org_unit']
        ),
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, subject['common']),
    ])

def generate_keys():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return public_key, private_key


def wrap(subject, public_key, private_key, certs):
    with tempfile.TemporaryDirectory() as tmpdir:
        ahdir = os.path.join(tmpdir, 'archive')
        os.mkdir(ahdir)
        if public_key:
            with open(os.path.join(ahdir, f'{subject}-pub.key'), 'wb') as f:
                f.write(public_key)

        if private_key:
            with open(os.path.join(ahdir, f'{subject}.key'), 'wb') as f:
                f.write(private_key)

        with open(os.path.join(ahdir, f'{subject}.cert'), 'wb') as f:
            for cert in certs:
                f.write(cert)

        shutil.make_archive(
            base_name=os.path.join(tmpdir, subject),
            format="zip",
            root_dir=ahdir,
        )

        return send_from_directory(tmpdir, f'{subject}.zip', as_attachment=True)


def parse_key_usage(key_usage):
    usage = defaultdict(bool)
    usage.update([(key, True) for key in key_usage])
    return x509.KeyUsage(
        digital_signature=usage['digitalSignature'],
        data_encipherment=usage['dataEncipherment'],
        key_agreement=usage['keyAgreement'],
        key_cert_sign=usage['keyCertSign'],
        crl_sign=usage['crlSign'],
        encipher_only=usage['encipherOnly'],
        decipher_only=usage['decipherOnly'],
        key_encipherment=usage['keyEncipherment'],
        content_commitment=usage['contentCommitment'],
    )


def parse_extended_key_usage(extended_key_usage):
    usages = []
    if 'serverAuth' in extended_key_usage:
        usages.append(x509.ExtendedKeyUsageOID.SERVER_AUTH)
    if 'clientAuth' in extended_key_usage:
        usages.append(x509.ExtendedKeyUsageOID.CLIENT_AUTH)
    if 'codeSigning' in extended_key_usage:
        usages.append(x509.ExtendedKeyUsageOID.CODE_SIGNING)
    if 'emailProtection' in extended_key_usage:
        usages.append(x509.ExtendedKeyUsageOID.EMAIL_PROTECTION)
    if 'timeStamping' in extended_key_usage:
        usages.append(x509.ExtendedKeyUsageOID.TIME_STAMPING)
    if 'ocspSigning' in extended_key_usage:
        usages.append(x509.ExtendedKeyUsageOID.OCSP_SIGNING)
    if 'anyExtendedKeyUsage' in extended_key_usage:
        usages.append(x509.ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE)
    return x509.ExtendedKeyUsage(usages)


def parse_general_name(name):
    typ, value = name['typ'], name['value']
    if typ == 'DNS':
        return x509.DNSName(value)
    if typ == 'RFC822':
        return x509.RFC822Name(value)
    return x509.UniformResourceIdentifier(value)


def parse_name_constraints(constraints):
    permitted, excluded = [], []
    if 'permitted' in constraints:
        for constraint in constraints['permitted']:
            permitted.append(parse_general_name(constraint))
    if 'excluded' in constraints:
        for constraint in constraints['excluded']:
            excluded.append(parse_general_name(constraint))
    return x509.NameConstraints(permitted, excluded)


def parse_subject_alt_name(alt_names):
    return x509.SubjectAlternativeName([parse_general_name(name) for name in alt_names])


def parse_access_desc(desc):
    if desc['method'] == 'OCSP':
        method = x509.AuthorityInformationAccessOID.OCSP
    else:
        method = x509.AuthorityInformationAccessOID.CA_ISSUERS
    return x509.AccessDescription(method, parse_general_name(desc['value']))


def parse_auth_info_access(info):
    return x509.AuthorityInformationAccess([parse_access_desc(desc) for desc in info])

def serialize_keys(public_key=None, private_key=None):
    serialized_private = None
    if private_key:
        serialized_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    serialized_public = None
    if public_key:
        serialized_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    return serialized_public, serialized_private

def generate(
    issuer,
    issuer_key,
    issuer_cert,
    subject,
    subject_key,
    key_usage,
    ext_key_usage,
    sub_alt_name,
    name_const,
    auth_info_access,
    ca=False,
):
    val_period = 730

    serial_number = x509.random_serial_number()
    valid_until = datetime.datetime.utcnow() + datetime.timedelta(days=int(val_period))

    builder = x509.CertificateBuilder() \
        .subject_name(subject) \
        .issuer_name(issuer) \
        .public_key(subject_key) \
        .serial_number(serial_number) \
        .not_valid_before(datetime.datetime.utcnow()) \
        .not_valid_after(valid_until)

    if ca:
        builder = builder\
            .add_extension(
                x509.BasicConstraints(True, None),
                critical=True
            ).add_extension(
                x509.SubjectKeyIdentifier.from_public_key(subject_key),
                critical=False
            )
    else:
        builder = builder \
            .add_extension(
                x509.BasicConstraints(False, None),
                critical=False
            )

    if ca:
        builder = builder \
            .add_extension(
                x509.AuthorityKeyIdentifier(
                    key_identifier=x509.SubjectKeyIdentifier.from_public_key(issuer_cert.public_key()).digest,
                    authority_cert_issuer=[x509.DirectoryName(issuer)],
                    authority_cert_serial_number=issuer_cert.serial_number
                ),
                critical=False
            )

    if key_usage:
        builder = builder.add_extension(key_usage, critical=False)

    if ext_key_usage:
        builder = builder.add_extension(ext_key_usage, critical=False)

    if sub_alt_name:
        builder = builder.add_extension(sub_alt_name, critical=False)

    if name_const:
        builder = builder.add_extension(name_const, critical=False)

    if auth_info_access:
        builder = builder.add_extension(auth_info_access, critical=False)

    return builder.sign(issuer_key, hashes.SHA256(), default_backend())


def get_certificate_by_pk(pk):
    return Record.query.filter_by(cert_pk=pk).one().cert

def list_certificates():
    certs = []
    for record in Record.query.filter_by(revoked_at=None).all():
        certs.append({
            'serialNumber': record.cert_pk,
            'commonName': record.common_name,
            'createdAt': record.created_at,
            'issuer': app.config.get('ISSUER', None)
        })
    return jsonify(certs)

def revoke_certificate(pk):
    record = Record.query.filter_by(cert_pk=pk).one()
    record.revoked_at = datetime.datetime.now()
    record.save()

