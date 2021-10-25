import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from dcr.scenario_utils.common_utils import random_alphanum


class OpenSshKey(object):
    """
    Represents an OpenSSH key pair.
    """

    def __init__(self, public_key: bytes, private_key: bytes):
        self._private_key = private_key
        self._public_key = public_key

    @property
    def private_key(self) -> bytes:
        return self._private_key

    @property
    def public_key(self) -> bytes:
        return self._public_key


class OpenSshKeyFactory(object):
    @staticmethod
    def create() -> OpenSshKey:
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        public_key = key.public_key().public_bytes(
            serialization.Encoding.OpenSSH,
            serialization.PublicFormat.OpenSSH
        )

        private_key = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )

        return OpenSshKey(public_key, private_key)


def generate_ssh_key_pair(key_prefix='dcr_id_rsa'):
    # New SSH public/private keys
    ssh_keys = OpenSshKeyFactory().create()

    private_key_file_name = '{0}_{1}'.format(key_prefix, random_alphanum(10))
    with open(private_key_file_name, 'wb') as fh:
        fh.write(ssh_keys.private_key)
    private_key_file = os.path.abspath(private_key_file_name)

    return ssh_keys.public_key.decode('utf-8'), private_key_file