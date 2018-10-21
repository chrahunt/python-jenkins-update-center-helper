import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography import x509
import pytest

from jenkins_update_center_helper.signer import sign
from .utils import generate_self_signed_cert


@pytest.fixture
def isolated_fs():
    with TemporaryDirectory() as d:
        os.chdir(d)
        yield


def test_hashes_match(isolated_fs):
    f = Path(__file__).parent / 'fixtures' / 'update-center.actual.json'
    obj = json.loads(f.read_text(encoding='utf-8'))
    signature = obj['signature']
    key, cert = generate_self_signed_cert()
    signed_data = sign(obj, key=key, certificate=cert)
    assert (
        signed_data['signature']['correct_digest'] ==
        signature['correct_digest'])
    assert (
        signed_data['signature']['correct_digest512'] ==
        signature['correct_digest512'])
