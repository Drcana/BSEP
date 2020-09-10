import re

from flask import current_app as app
from marshmallow import (
    Schema,
    ValidationError,
    fields,
)


ALLOWED_INPUT = re.compile(r'[\w,.&\'\"/@: ]+')


def validate_general_name_type(typ):
    if typ not in ['DNS', 'URI', 'RFC822']:
        raise ValidationError('Invalid general name type. Available types are DNS, URI and RFC822.')


def validate_access_desc_method(method):
    if method not in ['OCSP', 'CA_ISSUERS']:
        raise ValidationError('Invalid access description method. Available methods are OCSP and CA_ISSUERS.')


def validate_identifiers(identifier):
    if not ALLOWED_INPUT.fullmatch(identifier):
        print(identifier)
        raise ValidationError('Invalid identifier.')


class Subject(Schema):
    org = fields.String(load_from='organization', required=True, validate=validate_identifiers)
    org_unit = fields.String(load_from='organizationalUnit', required=True, validate=validate_identifiers)
    common = fields.String(load_from='commonName', required=True, validate=validate_identifiers)

    class Meta:
        strict = True


class GeneralName(Schema):
    typ = fields.String(load_from='type', required=True, validate=validate_general_name_type)
    value = fields.String(load_from='value', required=True, validate=validate_identifiers)

    class Meta:
        strict = True


class NameConstraint(Schema):
    permitted = fields.Nested(GeneralName, many=True, required=False)
    excluded = fields.Nested(GeneralName, many=True, required=False)

    class Meta:
        strict = True


class AccessDescription(Schema):
    method = fields.String(required=True, validate=validate_access_desc_method)
    value = fields.Nested(GeneralName, required=True)

    class Meta:
        strict = True


class IssueCertificateRequest(Schema):
    subject = fields.Nested(Subject, required=True)
    ca = fields.Boolean(load_from='certificationAuthority', required=False, missing=False)
    gen_keys = fields.Boolean(load_from='generateKeys', required=False, missing=True)
    key_usage = fields.List(
        fields.String(),
        load_from='keyUsage',
        required=False,
    )
    ext_key_usage = fields.List(
        fields.String(),
        load_from='extendedKeyUsage',
        required=False,
    )
    name_const = fields.Nested(
        NameConstraint,
        load_from='nameConstraints',
        required=False
    )
    sub_alt_name = fields.Nested(
        GeneralName,
        load_from='subjectAlternativeName',
        many=True,
        required=False
    )
    auth_info_access = fields.Nested(
        AccessDescription,
        load_from='authorityInformationAccess',
        many=True,
        required=False
    )
    public_key = fields.String(load_from='publicKey', required=False)

    class Meta:
        strict = True
