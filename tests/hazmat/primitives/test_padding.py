# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import contextlib
import sys
import threading

import pytest

from cryptography.exceptions import AlreadyFinalized
from cryptography.hazmat.primitives import padding

from .utils import IS_FREETHREADED_BUILD, run_threaded


class TestPKCS7:
    @pytest.mark.parametrize("size", [127, 4096, -2])
    def test_invalid_block_size(self, size):
        with pytest.raises(ValueError):
            padding.PKCS7(size)

    @pytest.mark.parametrize(
        ("size", "padded"),
        [
            (128, b"1111"),
            (128, b"1111111111111111"),
            (128, b"111111111111111\x06"),
            (128, b""),
            (128, b"\x06" * 6),
            (128, b"\x00" * 16),
        ],
    )
    def test_invalid_padding(self, size, padded):
        unpadder = padding.PKCS7(size).unpadder()
        with pytest.raises(ValueError):
            unpadder.update(padded)
            unpadder.finalize()

    def test_non_bytes(self):
        padder = padding.PKCS7(128).padder()
        with pytest.raises(TypeError):
            padder.update("abc")  # type: ignore[arg-type]
        unpadder = padding.PKCS7(128).unpadder()
        with pytest.raises(TypeError):
            unpadder.update("abc")  # type: ignore[arg-type]

    def test_zany_py2_bytes_subclass(self):
        class mybytes(bytes):  # noqa: N801
            def __str__(self):
                return "broken"

        str(mybytes())
        padder = padding.PKCS7(128).padder()
        data = padder.update(mybytes(b"abc")) + padder.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        unpadder.update(mybytes(data))
        assert unpadder.finalize() == b"abc"

    @pytest.mark.parametrize(
        ("size", "unpadded", "padded"),
        [
            (128, b"1111111111", b"1111111111\x06\x06\x06\x06\x06\x06"),
            (
                128,
                b"111111111111111122222222222222",
                b"111111111111111122222222222222\x02\x02",
            ),
            (128, b"1" * 16, b"1" * 16 + b"\x10" * 16),
            (128, b"1" * 17, b"1" * 17 + b"\x0f" * 15),
        ],
    )
    def test_pad(self, size, unpadded, padded):
        padder = padding.PKCS7(size).padder()
        result = padder.update(unpadded)
        result += padder.finalize()
        assert result == padded

    @pytest.mark.parametrize(
        ("size", "unpadded", "padded"),
        [
            (128, b"1111111111", b"1111111111\x06\x06\x06\x06\x06\x06"),
            (
                128,
                b"111111111111111122222222222222",
                b"111111111111111122222222222222\x02\x02",
            ),
            (128, b"1" * 16, b"1" * 16 + b"\x10" * 16),
            (128, b"1" * 17, b"1" * 17 + b"\x0f" * 15),
        ],
    )
    def test_unpad(self, size, unpadded, padded):
        unpadder = padding.PKCS7(size).unpadder()
        result = unpadder.update(padded)
        result += unpadder.finalize()
        assert result == unpadded

    def test_use_after_finalize(self):
        padder = padding.PKCS7(128).padder()
        b = padder.finalize()
        with pytest.raises(AlreadyFinalized):
            padder.update(b"")
        with pytest.raises(AlreadyFinalized):
            padder.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        unpadder.update(b)
        unpadder.finalize()
        with pytest.raises(AlreadyFinalized):
            unpadder.update(b"")
        with pytest.raises(AlreadyFinalized):
            unpadder.finalize()

    def test_large_padding(self):
        padder = padding.PKCS7(2040).padder()
        padded_data = padder.update(b"")
        padded_data += padder.finalize()

        for i in padded_data:
            assert i == 255

        unpadder = padding.PKCS7(2040).unpadder()
        data = unpadder.update(padded_data)
        data += unpadder.finalize()

        assert data == b""

    def test_bytearray(self):
        padder = padding.PKCS7(128).padder()
        unpadded = bytearray(b"t" * 38)
        padded = (
            padder.update(unpadded)
            + padder.update(unpadded)
            + padder.finalize()
        )
        unpadder = padding.PKCS7(128).unpadder()
        final = unpadder.update(padded) + unpadder.finalize()
        assert final == unpadded + unpadded


class TestANSIX923:
    @pytest.mark.parametrize("size", [127, 4096, -2])
    def test_invalid_block_size(self, size):
        with pytest.raises(ValueError):
            padding.ANSIX923(size)

    @pytest.mark.parametrize(
        ("size", "padded"),
        [
            (128, b"1111"),
            (128, b"1111111111111111"),
            (128, b"111111111111111\x06"),
            (128, b"1111111111\x06\x06\x06\x06\x06\x06"),
            (128, b""),
            (128, b"\x06" * 6),
            (128, b"\x00" * 16),
        ],
    )
    def test_invalid_padding(self, size, padded):
        unpadder = padding.ANSIX923(size).unpadder()
        with pytest.raises(ValueError):
            unpadder.update(padded)
            unpadder.finalize()

    def test_non_bytes(self):
        padder = padding.ANSIX923(128).padder()
        with pytest.raises(TypeError):
            padder.update("abc")  # type: ignore[arg-type]
        unpadder = padding.ANSIX923(128).unpadder()
        with pytest.raises(TypeError):
            unpadder.update("abc")  # type: ignore[arg-type]

    def test_zany_py2_bytes_subclass(self):
        class mybytes(bytes):  # noqa: N801
            def __str__(self):
                return "broken"

        str(mybytes())
        padder = padding.ANSIX923(128).padder()
        padder.update(mybytes(b"abc"))
        unpadder = padding.ANSIX923(128).unpadder()
        unpadder.update(mybytes(padder.finalize()))
        assert unpadder.finalize() == b"abc"

    @pytest.mark.parametrize(
        ("size", "unpadded", "padded"),
        [
            (128, b"1111111111", b"1111111111\x00\x00\x00\x00\x00\x06"),
            (
                128,
                b"111111111111111122222222222222",
                b"111111111111111122222222222222\x00\x02",
            ),
            (128, b"1" * 16, b"1" * 16 + b"\x00" * 15 + b"\x10"),
            (128, b"1" * 17, b"1" * 17 + b"\x00" * 14 + b"\x0f"),
        ],
    )
    def test_pad(self, size, unpadded, padded):
        padder = padding.ANSIX923(size).padder()
        result = padder.update(unpadded)
        result += padder.finalize()
        assert result == padded

    @pytest.mark.parametrize(
        ("size", "unpadded", "padded"),
        [
            (128, b"1111111111", b"1111111111\x00\x00\x00\x00\x00\x06"),
            (
                128,
                b"111111111111111122222222222222",
                b"111111111111111122222222222222\x00\x02",
            ),
        ],
    )
    def test_unpad(self, size, unpadded, padded):
        unpadder = padding.ANSIX923(size).unpadder()
        result = unpadder.update(padded)
        result += unpadder.finalize()
        assert result == unpadded

    def test_use_after_finalize(self):
        padder = padding.ANSIX923(128).padder()
        b = padder.finalize()
        with pytest.raises(AlreadyFinalized):
            padder.update(b"")
        with pytest.raises(AlreadyFinalized):
            padder.finalize()

        unpadder = padding.ANSIX923(128).unpadder()
        unpadder.update(b)
        unpadder.finalize()
        with pytest.raises(AlreadyFinalized):
            unpadder.update(b"")
        with pytest.raises(AlreadyFinalized):
            unpadder.finalize()

    def test_bytearray(self):
        padder = padding.ANSIX923(128).padder()
        unpadded = bytearray(b"t" * 38)
        padded = (
            padder.update(unpadded)
            + padder.update(unpadded)
            + padder.finalize()
        )
        unpadder = padding.ANSIX923(128).unpadder()
        final = unpadder.update(padded) + unpadder.finalize()
        assert final == unpadded + unpadded


class SwitchIntervalContext(contextlib.ContextDecorator):
    def __init__(self, interval):
        self.interval = interval

    def __enter__(self):
        self.orig_interval = sys.getswitchinterval()
        sys.setswitchinterval(self.interval)
        return self

    def __exit__(self, *exc):
        sys.setswitchinterval(self.orig_interval)
        return False


@SwitchIntervalContext(0.0000001)
@pytest.mark.parametrize(
    "algorithm",
    [
        padding.PKCS7,
        padding.ANSIX923,
    ],
)
def test_multithreaded_padding(algorithm):
    num_threads = 4
    chunk = b"abcd1234"
    data = chunk * 2048

    padder = algorithm(num_threads * 256).padder()
    validate_padder = algorithm(num_threads * 256).padder()
    expected_pad = validate_padder.update(data * num_threads)
    expected_pad += validate_padder.finalize()
    calculated_pad = b""

    b = threading.Barrier(num_threads)
    lock = threading.Lock()

    def pad_in_chunks(chunk_size):
        nonlocal calculated_pad
        index = 0
        b.wait()
        while index < len(data):
            try:
                new_content = padder.update(data[index : index + chunk_size])
                if IS_FREETHREADED_BUILD:
                    # rebinding a bytestring is racey on 3.13t
                    #
                    # the thread switch interval in this test isn't fast
                    # enough to trigger this on the GIL-enabled build maybe?
                    lock.acquire()
                    calculated_pad += new_content
                    lock.release()
                else:
                    calculated_pad += new_content
            except RuntimeError as e:
                # on the free-threaded build we might try to simultaneously
                # borrow the padder state at the same time as another thread
                # in that case, retry
                assert str(e) == "Already borrowed"
                assert IS_FREETHREADED_BUILD
                continue
            index += chunk_size

    def prepare_args(data, threadnum):
        chunk_size = len(data) // (2**threadnum)
        assert chunk_size > 0
        assert chunk_size % len(chunk) == 0
        return (chunk_size,)

    run_threaded(num_threads, data, chunk, pad_in_chunks, prepare_args)

    calculated_pad += padder.finalize()
    assert expected_pad == calculated_pad
