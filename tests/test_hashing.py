from __future__ import annotations

import hashlib

import pytest

from siftguard.evidence.hashing import sha256_file


def test_sha256_file_known_content(tmp_path):
    target = tmp_path / "sample.bin"
    payload = b"siftguard-test"
    target.write_bytes(payload)

    expected = hashlib.sha256(payload).hexdigest()
    assert sha256_file(target) == expected


def test_sha256_file_missing_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        sha256_file(tmp_path / "missing.bin")


def test_sha256_file_directory_raises(tmp_path):
    with pytest.raises(IsADirectoryError):
        sha256_file(tmp_path)
