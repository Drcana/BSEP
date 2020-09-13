import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec # has priority, is bigger than rsa
from cryptography.hazmat.primitives import serialization


def generate_key_pair():
    priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
    pub = priv.public_key()
    return priv, pub

def convertToBytes(pub_key=None, priv_key=None):
    if not pub_key and not priv_key:
        return False, False

    private_bytes = None
    if priv_key:
        private_bytes = priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    public_bytes = None
    if pub_key:
        public_bytes = pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    return public_bytes, private_bytes


def saveKeysToFile(file_name, public_key, private_key, output_dir='.'):
    pub_path = os.path.join(output_dir, f'{file_name}-pub.key')
    with open(pub_path, 'wb') as f:
        f.write(public_key)

    pri_path = os.path.join(output_dir, f'{file_name}.key')
    with open(pri_path, 'wb') as f:
        f.write(private_key)


if __name__ == '__main__':
    priv_k, pub_k = generate_key_pair()
    public_key, private_key = convertToBytes(pub_k, priv_k)
    saveKeysToFile(
        input('Insert name of public key file: '),
        public_key,
        private_key,
        os.path.join('.', 'keypair')
    )
