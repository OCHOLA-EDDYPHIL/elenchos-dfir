from __future__ import annotations

import hashlib

from siftguard.evidence.hashing import sha256_file


def test_sha256_file(tmp_path):
    target = tmp_path / "sample.bin"
    payload = b"siftguard-test"
    target.write_bytes(payload)

    expected = hashlib.sha256(payload).hexdigest()
    assert sha256_file(target) == expected
