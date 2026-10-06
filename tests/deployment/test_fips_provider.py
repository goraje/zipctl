"""Opt-in runtime evidence from the actual deployment's cryptography provider."""

import io
import os

import pytest
from cryptography.hazmat.backends.openssl.backend import backend

from zipctl import WZ_AES, BadZipFile, ZipFile, ZipFileExtra

pytestmark = pytest.mark.deployment


@pytest.mark.parametrize("bits", [128, 192, 256])
def test_aes_with_deployment_fips_provider(bits: int) -> None:
    if os.environ.get("ZIPCTL_REQUIRE_FIPS") != "1":
        pytest.skip(
            "set ZIPCTL_REQUIRE_FIPS=1 in the configured deployment environment"
        )
    # cryptography exposes no public FIPS-state API. Fail closed if this private
    # diagnostic changes; a successful round trip on its own is insufficient.
    assert getattr(backend, "_fips_enabled", False) is True, (
        "cryptography's actual OpenSSL backend does not report FIPS enabled"
    )
    print(backend.openssl_version_text())
    buffer = io.BytesIO()
    payload = b"deployment provider round trip" * 100
    with ZipFile(
        buffer, "w", encryption=WZ_AES, extra=ZipFileExtra(wz_aes_nbits=bits)
    ) as archive:
        archive.setpassword(b"deployment-validation-password")
        archive.writestr("file", payload)
    with ZipFile(buffer) as archive:
        assert archive.read("file", pwd=b"deployment-validation-password") == payload
    damaged = bytearray(buffer.getvalue())
    central = damaged.index(b"PK\x01\x02")
    damaged[central - 1] ^= 1  # authentication trailer
    with ZipFile(io.BytesIO(damaged)) as archive:
        with pytest.raises(BadZipFile):
            archive.read("file", pwd=b"deployment-validation-password")
