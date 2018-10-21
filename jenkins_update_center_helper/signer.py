"""Signing functions for generating Jenkins-compatible JSON files.
"""
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


def sign( # pylint: disable=too-many-arguments
        json_data: Optional[Union[dict, str, bytes]] = None,
        json_data_path: Optional[PathType] = None,
        key: Optional[KeyInput] = None,
        key_path: Optional[PathType] = None,
        password: Optional[Union[str, bytes]] = None,
        certificate: Optional[CertInput] = None,
        certificate_path: Optional[PathType] = None) -> bytes:
    """Generate Jenkins-compatible signed JSON data.

    The signature is embedded in the returned value.

    This method requires the json, a private key, and a certificate.
    Either the values themselves can be provided or paths to them
    (using the `_path`-suffixed variables).
    """
    def get_arg_or_path(arg, path_arg):
        if arg is None and path_arg is not None:
            return Path(path_arg).read_bytes()
        return arg

    # Handle json.
    json_data = get_arg_or_path(json_data, json_data_path)
    if json_data is None:
        raise ValueError(
            'One of `json_data` or `json_data_path` must be provided.')

    if isinstance(json_data, (bytes, str)):
        json_obj = json.loads(json_data)
    elif isinstance(json_data, dict):
        # Prevent mutating caller's object.
        json_obj = copy.deepcopy(json_data)
    else:
        raise TypeError(
            f'Parameter `json_data` has unexpected type {type(json_data)}')

    def ensure_bytes(arg):
        if isinstance(arg, str):
            return arg.encode('utf-8')
        if isinstance(arg, bytes):
            return arg
        return None

    # Handle private key.
    key = get_arg_or_path(key, key_path)
    if key is None:
        raise ValueError('One of `key` or `key_path` must be provided.')

    key_bytes = ensure_bytes(key)
    password_bytes = ensure_bytes(password)
    if key_bytes is not None:
        key = _decode_private_key(key_bytes, password_bytes)

    if not issubclass(type(key), RSAPrivateKey):
        raise TypeError(f'Parameter `key` has unexpected type {type(key)}')

    # Handle certificate.
    certificate = get_arg_or_path(certificate, certificate_path)
    if certificate is None:
        raise ValueError(
            'One of `certificate` or `certificate_path` must be provided.')

    certificate_bytes = ensure_bytes(certificate)
    if certificate_bytes is not None:
        certificate = _decode_certificate(certificate_bytes)

    if not issubclass(type(certificate), x509.Certificate):
        raise TypeError(
            f'Parameter `certificate` has unexpected type {type(certificate)}')

    return canonicalize_json(sign_internal(json_obj, key, [certificate]))


def sign_internal(
        obj: dict, key: KeyType, certificates: CertsType) -> dict:
    """Sign and embed signature, aligning with update-center2 implementation.

    The signature block is embedded in the provided object, which is also
    returned.
    """
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
        buf_size = 8192
        return data[:len(data) - (len(data) % buf_size)]

    def _convert_certificate(cert):
        return base64.b64encode(
            cert.public_bytes(
                encoding=serialization.Encoding.DER)).decode('utf-8')

    # update-center2 performs the following to sign the JSON files staged at
    # updates.jenkins.io:
    # 1. Canonicalization of JSON
    # 2. Digest generation
    # 3. Sign digest
    # 4. Embed digest, signature, and certificates into JSON.

    # Digest calculation does not include the signature block.
    obj.pop('signature', None)
    # the un-prefixed keys of the signature block were for older (<1.433,
    # pre-2011) versions of Jenkins that did not flush their output stream.
    json_bytes = canonicalize_json(obj)

    signature = {}
    # As mentioned in
    # https://github.com/jenkins-infra/update-center2/blob/f607589ab50d9c8d09ba84e0ed358b077abd0754/src/main/java/org/jvnet/hudson/update_center/Signer.java#L111
    # prior to Jenkins 1.433, the implementation was not flushing the output
    # stream prior to finalizing the digest, leaving some bytes off the end.
    # The digest and signature fields were left as-is for that incorrect
    # implementation, and new prefixed versions were introduced which have
    # the digests and signatures generated from the full contents.
    signature.update(_make_signature(_simulate_unflushed_stream(json_bytes)))
    signature.update(_make_signature(json_bytes, 'correct_'))
    signature['certificates'] = [
        _convert_certificate(c) for c in certificates]

    obj['signature'] = signature

    return obj


def canonicalize_json(obj: dict) -> bytes:
    """Generate JSON output compatible with
    net.sf.json.JSONObject.writeCanonical.
    """
    return json.dumps(
        obj,
        # Remove spaces from around separators.
        separators=(',', ':'),
        # Prevent \u escapes in encoded output.
        ensure_ascii=False,
        sort_keys=True).encode('utf-8')


def _decode_private_key(data, password=None):
    loader = serialization.load_pem_private_key
    if _is_der(data):
        loader = serialization.load_der_private_key
    return loader(data, password=password, backend=default_backend())


def _decode_certificate(data):
    loader = x509.load_pem_x509_certificate
    if _is_der(data):
        loader = x509.load_der_x509_certificate
    return loader(data, backend=default_backend())


def _is_der(data):
    der_magic = b"\x30\x82"
    return data.startswith(der_magic)
