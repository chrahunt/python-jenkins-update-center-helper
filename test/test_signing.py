import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography import x509
import pytest

import jenkins_update_center_helper.signer as signer
from .utils import generate_self_signed_cert


@pytest.fixture
def isolated_fs():
    with TemporaryDirectory() as d:
        os.chdir(d)
        yield


def test_signing(isolated_fs):
    f = Path(__file__).parent / 'fixtures' / 'update-center.actual.json'
    obj = json.loads(f.read_text(encoding='utf-8'))
    signature = obj['signature']
    key, cert = generate_self_signed_cert()
    signed_data_bytes = signer.sign(obj, key=key, certificate=cert)
    signed_data = json.loads(signed_data_bytes)
    assert (
        signed_data['signature']['digest'] ==
        signature['digest'])
    assert (
        signed_data['signature']['digest512'] ==
        signature['digest512'])
    assert (
        signed_data['signature']['correct_digest'] ==
        signature['correct_digest'])
    assert (
        signed_data['signature']['correct_digest512'] ==
        signature['correct_digest512'])
