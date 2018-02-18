# Copyright (C) 2016 Marco Giusti
# vim: sts=4:sw=4:et

import os.path
import unittest
import zipfile
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


_refs = []


class MyVerifyingZipFile(wheel.install.VerifyingZipFile):

    def __init__(self, file, mode='r', compression=zipfile.ZIP_STORED,
                 allowZip64=False):
        # import pdb; pdb.set_trace()
        _refs.append(self)
        super().__init__(file, mode, compression, allowZip64)


def restore(orig):
    wheel.install.VerifyingZipFile = orig


def close_all():
    for fp in _refs:
        fp.close()
    _refs[:] = []


class TestWheelSign(unittest.TestCase):

    def test_verify_wheel(self):
        import gc; gc.collect(2)
        verify_wheel(abspath(WHEELFILE))
        import gc; gc.collect(2)

    def patch_VerifyingZipFile(self):
        # NOTE: because wheel.install.WheelFile does not properly close
        # the underling zip file, patch the module to keep trace of the
        # references and close them at the end of the test.

        # import pdb; pdb.set_trace()
        self.addCleanup(restore, wheel.install.VerifyingZipFile)
        self.addCleanup(close_all)
        wheel.install.VerifyingZipFile = MyVerifyingZipFile

    # def test_self_signed(self):
    #     self.patch_VerifyingZipFile()
    #     self.assertRaisesRegex(
    #         wheel_sign.VerificationError,
    #         'self signed certificate',
    #         wheel_sign.verify_wheel,
    #         abspath(WHEELFILE),
    #         True
    #     )

    # from now on use the utility to include our certificate in the list of
    # lookup locations

    # def test_additional_file(self):
    #     import gc; gc.collect(2)
    #     # self.patch_VerifyingZipFile()
    #     # The wheel contains an additional file with no hash
    #     whl = abspath('additional_file', WHEELFILE)
    #     # import pdb; pdb.set_trace()
    #     self.assertRaisesRegex(
    #         wheel_sign.VerificationError,
    #         'No expected hash for file '
    #         "'wheel_sign-0.3.dist-info/additional_file'",
    #         verify_wheel,
    #         whl,
    #     )
    #     # import gc; gc.collect(2)

    def test_no_record_file(self):
        import gc; gc.collect(2)
        self.patch_VerifyingZipFile()
        # The wheel has no RECORD file
        whl = abspath('no_record', WHEELFILE)
        self.assertRaisesRegex(
            wheel_sign.VerificationError,
            'RECORD file not found',
            verify_wheel,
            whl,
        )
        import gc; gc.collect(2)

    def test_no_record_file2(self):
        self.assertRaisesRegex(
            wheel_sign.VerificationError,
            'RECORD file not found',
            wheel_sign.SignatureVerifier.from_wheel,
            wheel.install.WheelFile(abspath('no_record', WHEELFILE)),
        )

    def test_no_signature(self):
        import gc; gc.collect(2)
        self.patch_VerifyingZipFile()
        # The wheel has no signature
        whl = abspath('no_signature', WHEELFILE)
        self.assertRaisesRegex(
            wheel_sign.VerificationError,
            'RECORD.SF not found',
            verify_wheel,
            whl,
        )
        import gc; gc.collect(2)

    def test_no_certificate(self):
        import gc; gc.collect(2)
        self.patch_VerifyingZipFile()
        # The wheel has no certificate
        whl = abspath('no_certificate', WHEELFILE)
        self.assertRaisesRegex(
            wheel_sign.VerificationError,
            'certificate not found',
            verify_wheel,
            whl,
        )
        import gc; gc.collect(2)

    def test_invalid_signature(self):
        import gc; gc.collect(2)
        self.patch_VerifyingZipFile()
        # The signature has been tempered
        whl = abspath('invalid_signature', WHEELFILE)
        self.assertRaisesRegex(
            wheel_sign.VerificationError,
            'invalid signature',
            verify_wheel,
            whl,
        )
        import gc; gc.collect(2)

#     def test_invalid_certificate(self):
#         import gc; gc.collect(2)
#         self.patch_VerifyingZipFile()
#         # Use a different certificate
#         whl = abspath('invalid_certificate', WHEELFILE)
#         self.assertRaisesRegex(
#             wheel_sign.VerificationError,
#             'invalid signature',
#             verify_wheel,
#             whl,
#         )
#         import gc; gc.collect(2)
