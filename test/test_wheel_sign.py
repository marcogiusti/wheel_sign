# Copyright (C) 2016 Marco Giusti
# vim: sts=4:sw=4:et

import os.path
import unittest
import wheel.install
import wheel_sign


CERTFILE = 'cert.pem'
SIGNFILE = 'privkey.pem'
WHEELFILE = 'wheel_sign-0.3-py3-none-any.whl'


def abspath(*parts):
    return os.path.join(os.path.dirname(__file__), *parts)


def verify_wheel(wheelfile, exclude_default_paths=False, include_paths=(),
                 hostname=None, pwd=None):
    # small utility to include CERTFILE in the list of lookup locations because
    # we always use the same self signed certificate
    if not include_paths:
        include_paths = [(os.fsencode(abspath(CERTFILE)), None)]
    return wheel_sign.verify_wheel(
        wheelfile,
        exclude_default_paths,
        include_paths,
        hostname,
        pwd
    )


class TestWheelSign(unittest.TestCase):

    def test_verify_wheel(self):
        verify_wheel(abspath(WHEELFILE))

    def test_self_signed(self):
        self.assertRaisesRegex(
            wheel_sign.VerificationError,
            'self signed certificate',
            wheel_sign.verify_wheel,
            abspath(WHEELFILE),
            True
        )

    # from now on use the utility to include our certificate in the list of
    # lookup locations

    def test_additional_file(self):
        # The wheel contains an additional file with no hash
        whl = abspath('additional_file', WHEELFILE)
        # import pdb; pdb.set_trace()
        self.assertRaisesRegex(
            wheel_sign.VerificationError,
            'No expected hash for file '
            "'wheel_sign-0.3.dist-info/additional_file'",
            verify_wheel,
            whl,
        )

    def test_no_record_file(self):
        # The wheel has no RECORD file
        whl = abspath('no_record', WHEELFILE)
        self.assertRaisesRegex(
            wheel_sign.VerificationError,
            'RECORD file not found',
            verify_wheel,
            whl,
        )

    def test_no_record_file2(self):
        self.assertRaisesRegex(
            wheel_sign.VerificationError,
            'RECORD file not found',
            wheel_sign.SignatureVerifier.from_wheel,
            wheel.install.WheelFile(abspath('no_record', WHEELFILE)),
        )

    def test_no_signature(self):
        # The wheel has no signature
        whl = abspath('no_signature', WHEELFILE)
        self.assertRaisesRegex(
            wheel_sign.VerificationError,
            'RECORD.SF not found',
            verify_wheel,
            whl,
        )

    def test_no_certificate(self):
        # The wheel has no certificate
        whl = abspath('no_certificate', WHEELFILE)
        self.assertRaisesRegex(
            wheel_sign.VerificationError,
            'certificate not found',
            verify_wheel,
            whl,
        )

    def test_invalid_signature(self):
        # The signature has been tempered
        whl = abspath('invalid_signature', WHEELFILE)
        self.assertRaisesRegex(
            wheel_sign.VerificationError,
            'invalid signature',
            verify_wheel,
            whl,
        )

#     def test_invalid_certificate(self):
#         # Use a different certificate
#         whl = abspath('invalid_certificate', WHEELFILE)
#         self.assertRaisesRegex(
#             wheel_sign.VerificationError,
#             'invalid signature',
#             verify_wheel,
#             whl,
#         )
