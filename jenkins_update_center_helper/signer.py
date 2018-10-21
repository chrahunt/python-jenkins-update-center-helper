import base64
import binascii
import copy
import json
from pathlib import Path
from typing import Optional, Type, Union

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPrivateKeyWithSerialization


PathType = Union[str, Path]
KeyType = Union[RSAPrivateKeyWithSerialization, RSAPrivateKey]
CertType = x509.Certificate


def sign(
        update_center_json: Optional[dict]=None,
        update_center_json_path: Optional[PathType]=None,
        key: Optional[Union[str, bytes, KeyType]]=None,
        key_path: Optional[PathType]=None,
        password: Optional[Union[str, bytes]]=None,
        certificate: Optional[Union[str, bytes, CertType]]=None,
        certificate_path: Optional[PathType]=None) -> dict:
    """Sign provided update-center.json object and return with embedded 
    signature.

    This method requires the update-center json, a private key, and a
    certificate. Either the values themselves can be provided or paths to
    them (using the `_path` variables).
    :param update_center_json the object derived from update-center.json.
    :param update_center_json_path the object derived from update-center.json.
    """
    if update_center_json is not None:
        obj = copy.deepcopy(update_center_json)
    elif update_center_json_path is not None:
        with open(update_center_json_path, encoding='utf-8') as f:
            obj = json.load(f)
    else:
        raise ValueError(
            'One of `upate_center_json` or `update_center_json_path` must be'
            ' provided.')

    def get_arg_or_path(arg, path_arg):
        if arg is None and path_arg is not None:
            return Path(path_arg).read_bytes()
        return arg

    def ensure_bytes(arg):
        if type(arg) == str:
            return arg.encode('utf-8')
        if type(arg) == bytes:
            return arg

    # Handle private key.
    key = get_arg_or_path(key, key_path)
    if key is None:
        raise ValueError('One of `key` or `key_path` must be provided.')

    key_bytes = ensure_bytes(key)
    password_bytes = ensure_bytes(password)
    if key_bytes is not None:
        key = _decode_private_key(key_bytes, password_bytes)

    if not issubclass(type(key), RSAPrivateKey):
        raise ValueError('Unknown type for key')

    # Handle certificate.
    certificate = get_arg_or_path(certificate, certificate_path)
    if certificate is None:
        raise ValueError(
            'One of `certificate` or `certificate_path` must be provided.')

    certificate_bytes = ensure_bytes(certificate)
    if certificate_bytes is not None:
        certificate = _decode_certificate(certificate_bytes)

    if not issubclass(type(certificate), x509.Certificate):
        raise ValueError('Unknown type for certificate')

    return really_sign(obj, key, certificate)


def really_sign(obj: dict, key: KeyType, certificate: CertType) -> dict:
    def _sign(hash_type):
        hasher = hashes.Hash(hash_type, default_backend())
        hasher.update(s)
        digest = hasher.finalize()
        # PKCS1v15 is used for compatibility with the SHA*withRSA used in
        # update-center2.
        signature = key.sign(
            digest, padding.PKCS1v15(), utils.Prehashed(hash_type))
        return digest, signature

    obj.pop('signature', None)
    s = _canonicalize_json(obj)
    digest1, sig1 = _sign(hashes.SHA1())
    digest512, sig512 = _sign(hashes.SHA512())
    signature = {
        # We only implement the 'correct_'-prefixed versions for now.
        'correct_digest': base64.b64encode(digest1).decode('utf-8'),
        'correct_digest512': binascii.hexlify(digest512),
        'correct_signature': base64.b64encode(sig1).decode('utf-8'),
        'correct_signature512': binascii.hexlify(sig512),
        'certificate': base64.b64encode(
            certificate.public_bytes(
                encoding=serialization.Encoding.DER)).decode('utf-8'),
    }
    obj['signature'] = signature
    return obj


def _canonicalize_json(obj):
    return json.dumps(obj, sort_keys=True).encode('utf-8')


def _decode_private_key(data, password=None):
    fn = serialization.load_pem_private_key
    if _is_der(data):
        fn = serialization.load_der_private_key
    return fn(data, password=password, backend=default_backend())


def _decode_certificate(data):
    fn = x509.load_pem_x509_certificate
    if _is_der(data):
        fn = x509.load_der_x509_certificate
    return fn(data, backend=default_backend())
        

def _is_der(data):
    DER_MAGIC = b"\x30\x82"
    return data.startswith(DER_MAGIC)
