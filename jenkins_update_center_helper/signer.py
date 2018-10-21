import base64
import binascii
import copy
import json
from pathlib import Path
from typing import List, Optional, Union

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.primitives.asymmetric.rsa import (
        RSAPrivateKey, RSAPrivateKeyWithSerialization)


PathType = Union[str, Path]
KeyType = Union[RSAPrivateKeyWithSerialization, RSAPrivateKey]
KeyInput = Union[str, bytes, KeyType]
CertType = x509.Certificate
CertsType = List[CertType]
CertInput = Union[str, bytes, CertType]


def sign(
        json_data: Optional[dict]=None,
        json_data_path: Optional[PathType]=None,
        key: Optional[KeyInput]=None,
        key_path: Optional[PathType]=None,
        password: Optional[Union[str, bytes]]=None,
        certificate: Optional[CertInput]=None,
        certificate_path: Optional[PathType]=None) -> dict:
    """Sign provided json object and return with embedded
    signature.

    This method requires the json, a private key, and a certificate.
    Either the values themselves can be provided or paths to them
    (using the `_path`-suffixed variables).
    """
    if json_data is not None:
        obj = copy.deepcopy(json_data)
    elif json_data_path is not None:
        with open(json_data_path, encoding='utf-8') as f:
            obj = json.load(f)
    else:
        raise ValueError(
            'One of `json_data` or `json_data_path` must be provided.')

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

    return sign_internal(obj, key, [certificate])


def sign_internal(
        obj: dict, key: KeyType, certificates: CertsType) -> dict:
    def _sign(data, hash_type):
        hasher = hashes.Hash(hash_type, default_backend())
        hasher.update(data)
        digest = hasher.finalize()
        # PKCS1v15 is used for compatibility with the SHA*withRSA used in
        # update-center2.
        signature = key.sign(
            digest, padding.PKCS1v15(), utils.Prehashed(hash_type))
        return digest, signature

    def _make_signature(data, prefix=''):
        digest1, sig1 = _sign(data, hashes.SHA1())
        digest512, sig512 = _sign(data, hashes.SHA512())
        return {
            f'{prefix}digest': base64.b64encode(digest1).decode('utf-8'),
            f'{prefix}digest512': binascii.hexlify(digest512).decode('utf-8'),
            f'{prefix}signature': base64.b64encode(sig1).decode('utf-8'),
            f'{prefix}signature512': binascii.hexlify(sig512).decode('utf-8'),
        }

    def _simulate_unflushed_stream(data):
        # OutputStreamWriter flushes at 8192 byte boundaries so we take all
        # but the last unfilled chunk.
        BUF_SIZE = 8192
        return data[:len(data) - (len(data) % BUF_SIZE)]

    def _convert_certificate(cert):
        return base64.b64encode(
            cert.public_bytes(
                encoding=serialization.Encoding.DER)).decode('utf-8')

    # Hash calculation does not include the signature block.
    obj.pop('signature', None)
    # As mentioned in
    # https://github.com/jenkins-infra/update-center2/blob/f607589ab50d9c8d09ba84e0ed358b077abd0754/src/main/java/org/jvnet/hudson/update_center/Signer.java#L111
    # the un-prefixed keys of the signature block were for older (<1.433,
    # pre-2011) versions of Jenkins that did not flush their output stream.
    s = _canonicalize_json(obj)

    signature = {
        'certificates': [_convert_certificate(c) for c in certificates]
    }
    signature.update(_make_signature(_simulate_unflushed_stream(s)))
    signature.update(_make_signature(s, 'correct_'))
    obj['signature'] = signature

    return obj


def _canonicalize_json(obj):
    return json.dumps(
        obj,
        # Remove spaces from around separators.
        separators=(',', ':'),
        # Prevent \u escapes in encoded output.
        ensure_ascii=False,
        sort_keys=True).encode('utf-8')


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
