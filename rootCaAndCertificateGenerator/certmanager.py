import datetime
import json
import os
import shutil
import sys
from collections import defaultdict
from io import StringIO, BytesIO

import pem
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

from keymanager import convertToBytes, saveKeysToFile, generate_key_pair


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
    val_period,
    ca=False,
    root=False
):
    serial_number = x509.random_serial_number()
    valid_until = datetime.datetime.utcnow() + \
                  datetime.timedelta(days=int(val_period))
    print("KLJUC", subject_key)
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

    if ca and not root:
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

    cert = builder.sign(issuer_key, hashes.SHA256(), default_backend())

    return cert


def load_certificate(certificate):
    cert = str(pem.parse_file(certificate)[0])
    stream = BytesIO(bytes(cert, encoding='utf-8'))
    return x509.load_pem_x509_certificate(stream.read(), default_backend())


def parse_issuer(issuer):
    if isinstance(issuer, dict):
        country = []
        if 'country' in issuer and issuer['country']:
            country.append(
                x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, issuer['country'])
            )
        return x509.Name(country + [
            x509.NameAttribute(
                x509.oid.NameOID.ORGANIZATION_NAME, issuer['organization']
            ),
            x509.NameAttribute(
                x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME,
                issuer['organizationalUnit']
            ),
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, issuer['commonName']),
        ])
    elif isinstance(issuer, str):
        return load_certificate(issuer).subject
    else:
        raise ValueError('Issuer field unprocessable. Object or string expected.')


def parse_subject(subject):
    if not isinstance(subject, dict):
        raise ValueError('Subject field unprocessable. Object expected.')
    country = []
    if 'country' in subject and subject['country']:
        country.append(
            x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, subject['country'])
        )
    return x509.Name(country + [
        x509.NameAttribute(
            x509.oid.NameOID.ORGANIZATION_NAME, subject['organization']
        ),
        x509.NameAttribute(
            x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME,
            subject['organizationalUnit']
        ),
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, subject['commonName']),
    ])


def parse_key_usage(key_usage):
    if not isinstance(key_usage, list):
        raise ValueError('Key usage field unprocessable. List of strings expected.')
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
    if not isinstance(extended_key_usage, list):
        raise ValueError('Extended key usage field unprocessable. List of strings expected.')
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
    if not isinstance(name, dict):
        raise ValueError('General name unprocessable. Object expected.')
    typ, value = name['type'], name['value']
    if typ == 'DNS':
        return x509.DNSName(value)
    if typ == 'rfc822name':
        return x509.RFC822Name(value)
    if typ == 'URI':
        return x509.UniformResourceIdentifier(value)
    raise ValueError(f'General name {typ} not recognized or not supported.')


def parse_name_constraints(constraints):
    if not isinstance(constraints, dict):
        raise ValueError('Name constraints field unprocessable. Object expected.')
    permitted, excluded = [], []
    if 'permitted' not in constraints and 'excluded' not in constraints:
        raise UserWarning('Neither permitted nor excluded constraints present, please inspect request for errors.')
    if 'permitted' in constraints:
        if not isinstance(constraints['permitted'], list):
            raise ValueError('Permitted constraints field unprocessable. List of objects expected.')
        for constraint in constraints['permitted']:
            permitted.append(parse_general_name(constraint))
    if 'excluded' in constraints:
        if not isinstance(constraints['excluded'], list):
            raise ValueError('Excluded constraints field unprocessable. List of objects expected.')
        for constraint in constraints['excluded']:
            excluded.append(parse_general_name(constraint))
    return x509.NameConstraints(permitted, excluded)


def parse_subject_alt_name(alt_names):
    if not isinstance(alt_names, list):
        raise ValueError('Subject alternative name field unprocessable. List of objects expected.')
    return x509.SubjectAlternativeName([parse_general_name(name) for name in alt_names])


def parse_access_desc(desc):
    if 'method' not in desc:
        raise ValueError('Access description must contain \'method\' field.')

    method = desc['method']
    if method != 'OCSP' and method !='CA_ISSUERS':
        raise ValueError('Available methods for access description are OCSP and CA_ISSUERS')

    if method == 'OCSP':
        method = x509.AuthorityInformationAccessOID.OCSP
    else:
        method = x509.AuthorityInformationAccessOID.CA_ISSUERS

    if 'value' not in desc:
        raise ValueError('Access description must contain \'value\' field.')

    return x509.AccessDescription(method, parse_general_name(desc['value']))


def parse_auth_info_access(info):
    if not isinstance(info, list):
        raise ValueError('Authority information access field unprocessable. List of objects expected.')
    return x509.AuthorityInformationAccess([parse_access_desc(desc) for desc in info])


def persist(out_dir, certs, name):
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, f'{name}.crt'), 'wb') as f:
        for cert in certs:
            f.write(cert)
        f.flush()


def compress(dir_name, zip_name):
    if not os.path.exists(dir_name):
        raise ValueError(f'Directory \'{dir_name}\' doesn\'t exist.')
    shutil.make_archive(
        base_name=os.path.join(dir_name, zip_name),
        format="zip",
        root_dir=dir_name,
    )


def load_private_key(path):
    with open(path, 'rb') as f:
        return serialization.load_pem_private_key(
            data=f.read(),
            password=None,
            backend=default_backend()
        )


def load_public_key(path):
    with open(path, 'rb') as f:
        return serialization.load_pem_public_key(
            data=f.read(),
            backend=default_backend()
        )


def load_keys(keys, private_only):
    if 'private' not in keys:
        raise ValueError('Private key not provided.')

    private = load_private_key(keys['private'])
    if private_only:
        return None, private

    if 'public' not in keys:
        raise ValueError('Public key not provided.')

    return load_public_key(keys['public']), private


def process(req):
    if 'issuer' not in req:
        raise ValueError('Issuer field is mandatory when request is not self signing.')
    issuer = parse_issuer(req['issuer'])

    self_signed = req.get('selfSigned', False)
    if self_signed:
        if 'subject' in req:
            raise UserWarning('Certificate is marked as self signed and subject field is provided.'
                              'This may not be a desired behaviour, please inspect request for errors.')
        subject = issuer
    elif 'subject' in req:
        subject = parse_subject(req['subject'])
    else:
        raise ValueError('Subject field is mandatory when request is not self signing.')

    key_usage = None
    if 'keyUsage' in req:
        key_usage = parse_key_usage(req['keyUsage'])

    ext_key_usage = None
    if 'extendedKeyUsage' in req:
        ext_key_usage = parse_extended_key_usage(req['extendedKeyUsage'])

    sub_alt_name = None
    if 'subjectAlternativeName' in req:
        sub_alt_name = parse_subject_alt_name(req['subjectAlternativeName'])

    name_const = None
    if 'nameConstraints' in req:
        name_const = parse_name_constraints(req['nameConstraints'])

    auth_info_access = None
    if 'authorityInfoAccess' in req:
        auth_info_access = parse_auth_info_access(req['authorityInfoAccess'])

    ca = req.get('CA', False)
    root = req.get('rootCA', False)
    gen_keys = req.get('generateKeys', True)

    if 'validityPeriod' not in req:
        raise ValueError('Validity period field is mandatory.')

    val_period = req['validityPeriod']

    to_zip = req.get('zip', True)

    issuer_cert = None
    if not root:
        issuer_cert = load_certificate(req['issuer'])

    subject_public, subject_private = None, None
    if gen_keys:
        subject_private, subject_public = generate_key_pair()
    else:
        if 'subjectKey' not in req:
            raise ValueError('Subject key not provided.')
        subject_public = load_public_key(req['subjectKey'])

    issuer_key = None
    if self_signed:
        issuer_key = subject_private
    else:
        if 'issuerKey' not in req:
            raise ValueError('Issuer key not provided.')
        issuer_key = load_private_key(req['issuerKey'])

    cert = generate(
        issuer,
        issuer_key,
        issuer_cert,
        subject,
        subject_public,
        key_usage,
        ext_key_usage,
        sub_alt_name,
        name_const,
        auth_info_access,
        val_period,
        ca,
        root
    )

    name = req.get('name', 'default')

    out_dir = os.path.join('output', name)
    certs = [cert.public_bytes(serialization.Encoding.PEM)]
    if not self_signed and issuer_cert.subject != issuer_cert.issuer:
        for c in pem.parse_file(req['issuer']):
            certs.append(bytes(str(c), encoding='utf-8'))
    persist(out_dir, certs, name)

    ser_pub, ser_pri = convertToBytes(subject_public, subject_private)
    saveKeysToFile(name, ser_pub, ser_pri, out_dir)

    if to_zip:
        compress(out_dir, name)


if __name__ == '__main__':
    with open(sys.argv[1], 'r') as f:
        requests = json.load(f)

    for request in requests:
        process(request)
