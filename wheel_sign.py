#!/usr/bin/env python
# vim: sts=4:sw=4:et
# Copyright (C) 2016 Marco Giusti

from functools import partial
from itertools import zip_longest
import zipfile

from cryptography import x509
from cryptography.exceptions import InvalidSignature
# As now, 17 Feb 2018, OpenSSL is the only supported backend and we use anyway
# the private API. Use it where it was the default_backend call.
from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding, dsa, rsa, ec
from service_identity.cryptography import verify_certificate_hostname
import wheel.install


__version__ = '0.3'
__author__ = 'Marco Giusti'
__all__ = [
    'VerificationError', 'InvalidCertificate', 'SignatureVerifier',
    'WheelVerifier', 'verify_wheel', 'main', 'sign_wheel'
]


_ffi = backend._ffi
_lib = backend._lib


class VerificationError(Exception):
    pass


class InvalidCertificate(VerificationError):
    pass


class InvalidFile(VerificationError):
    pass


def _record(wheelfile):
    '''Return the record file name inside the wheel.'''

    return wheelfile.record_name


def _certfile(wheelfile):
    '''Return the certificate file name inside the wheel.'''

    return _record(wheelfile) + '.PEM'


def _signfile(wheelfile):
    '''Return the signature file name inside the wheel.'''

    return _record(wheelfile) + '.SF'


class SignatureVerifier:

    def __init__(self, certificate, default_paths=False, lookup_locations=[],
                 checkers=[]):
        self._certificate = certificate
        self._default_paths = default_paths
        self._lookup_locations = lookup_locations
        self._checkers = checkers

    @classmethod
    def from_pem(cls, data):
        '''Build the verifier from a PEM serialized certificate.

        @raise InvalidCertificate:
        '''

        try:
            return cls(x509.load_pem_x509_certificate(data, backend))
        except ValueError as exc:
            raise InvalidCertificate(str(exc))

    @classmethod
    def from_wheel(cls, wheelfile, pwd=None):
        '''Build the verifier from a signed wheel file.

        @raise InvalidCertificate:
        @raise InvalidFile:
        '''

        cert = _certfile(wheelfile)
        try:
            wheelfile.zipfile.set_expected_hash(cert, None)
        except KeyError as exc:
            raise InvalidFile('RECORD file not found')
        try:
            certificate = wheelfile.zipfile.read(cert)
            return cls.from_pem(certificate)
        except (zipfile.BadZipfile, wheel.install.BadWheelFile) as exc:
            raise InvalidFile(str(exc))
        except KeyError as exc:
            raise InvalidFile('certificate not found')

    @classmethod
    def from_wheel_verifier(cls, wheel_verifier):
        return cls.from_wheel(wheel_verifier._wheelfile)

    def add_default_paths(self):
        return self.__class__(
            self._certificate,
            default_paths=True,
            lookup_locations=self._lookup_locations,
            checkers=self._checkers
        )

    def add_location(self, file=None, path=None):
        '''
        @raise AssertionError:
        '''

        assert file is not None or path is not None
        if file is None:
            file = _ffi.NULL
        if path is None:
            path = _ffi.NULL
        return self.__class__(
            self._certificate,
            default_paths=self._default_paths,
            lookup_locations=self._lookup_locations + [(file, path)],
            checkers=self._checkers
        )

    def add_check(self, check):
        assert callable(check)
        return self.__class__(
            self._certificate,
            default_paths=self._default_paths,
            lookup_locations=self._lookup_locations,
            checkers=self._checkers + [check]
        )

    def verify_certificate(self):
        '''
        @raise RuntimeError:
        @raise InvalidCertificate:
        '''

        store = _lib.X509_STORE_new()
        if store == _ffi.NULL:
            raise RuntimeError('X509_STORE_new')
        store = _ffi.gc(store, _lib.X509_STORE_free)
        if self._default_paths:
            if _lib.X509_STORE_set_default_paths(store) != 1:
                raise RuntimeError('X509_STORE_set_default_paths')
        for file, path in self._lookup_locations:
            if _lib.X509_STORE_load_locations(store, file, path) != 1:
                raise RuntimeError('X509_STORE_load_locations')
        ctx = _lib.X509_STORE_CTX_new()
        if ctx == _ffi.NULL:
            raise RuntimeError('X509_STORE_CTX_new')
        ctx = _ffi.gc(ctx, _lib.X509_STORE_CTX_free)
        x509 = self._certificate._x509
        if _lib.X509_STORE_CTX_init(ctx, store, x509, _ffi.NULL) != 1:
            raise RuntimeError('X509_STORE_CTX_init')
        if _lib.X509_verify_cert(ctx) != 1:
            code = _lib.X509_STORE_CTX_get_error(ctx)
            msg = _ffi.string(_lib.X509_verify_cert_error_string(code))
            raise InvalidCertificate(msg.decode('ascii', 'replace'))
        # TODO: better interface and error control
        for check in self._checkers:
            check(self._certificate)

    def verify_signature(self, data, signature):
        '''
        @raise RuntimeError:
        @raise VerificationError
        '''

        pub_key = self._certificate.public_key()
        try:
            if isinstance(pub_key, rsa.RSAPublicKey):
                pub_key.verify(
                    signature,
                    data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            elif isinstance(pub_key, dsa.DSAPublicKey):
                pub_key.verify(signature, data, hashes.SHA256())
            elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                pub_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            else:
                raise RuntimeError('Unknow public key instance')
        except InvalidSignature:
            raise VerificationError('invalid signature')

    def verify(self, data, signature):
        self.verify_certificate()
        self.verify_signature(data, signature)


class WheelVerifier:

    def __init__(self, wheelfile):
        self._wheelfile = wheelfile
        try:
            self._zipfile = zf = wheelfile.zipfile
        except KeyError:
            raise InvalidFile('RECORD file not found')
        zf.strict = True
        zf.set_expected_hash(_signfile(wheelfile), None)
        zf.set_expected_hash(_certfile(wheelfile), None)

    @classmethod
    def from_file(cls, filename, fp):
        try:
            return cls(wheel.install.WheelFile(filename, fp))
        except (wheel.install.BadWheelFile, zipfile.BadZipfile) as exc:
            raise InvalidFile(str(exc))

    def verify_file(self, name, pwd=None):
        try:
            fp = self._zipfile.open(name, pwd=pwd)
            data = 'start loop'  # initial data is ignored
            # consume the data and rely on VerifyingZipFile to perform
            # the check
            while data:
                data = fp.read(4096)
        except (wheel.install.BadWheelFile, zipfile.BadZipfile) as exc:
            raise InvalidFile(str(exc))

    def verify(self, pwd=None):
        '''Verify the content of a wheel file.
        '''
        for name in self._zipfile.namelist():
            self.verify_file(name, pwd)

    def namelist(self):
        return self._zipfile.namelist()

    def _read_file(self, name):
        try:
            return self._zipfile.read(name)
        except KeyError:
            raise InvalidFile('file {0} not found'.format(name))
        except zipfile.BadZipfile as exc:
            raise InvalidFile(str(exc))

    def signature(self):
        return self._read_file(_signfile(self._wheelfile))

    def certificate(self):
        return self._read_file(_certfile(self._wheelfile))

    def records(self):
        return self._read_file(_record(self._wheelfile))


def verify_wheel(wheelfile, exclude_default_paths=False, include_paths=(),
                 hostname=None, pwd=None):
    with open(wheelfile, 'rb') as fp:
        wheel_verifier = WheelVerifier.from_file(wheelfile, fp)
        verifier = SignatureVerifier.from_wheel_verifier(wheel_verifier)
        if not exclude_default_paths:
            verifier = verifier.add_default_paths()
        if include_paths:
            for file, path in include_paths:
                verifier = verifier.add_location(file, path)
        if hostname:
            check = partial(verify_certificate_hostname, hostname=hostname)
            verifier = verifier.add_check(check)
        # verify the signature for the record file
        verifier.verify(wheel_verifier.records(), wheel_verifier.signature())
        # verify that the files in the record file
        wheel_verifier.verify(pwd)


def _verify_wheel_cmdline(args):
    if args.password:
        import getpass
        password = getpass.getpass()
    else:
        password = None
    paths = zip_longest(
        args.include_file,
        args.include_dir,
        fillvalue=_ffi.NULL
    )
    try:
        verify_wheel(
            wheelfile=args.wheelfile,
            exclude_default_paths=args.exclude_default_paths,
            include_paths=paths,
            hostname=args.hostname,
            pwd=password
        )
    except VerificationError as exc:
        return str(exc)


def _sign(data, privkey):
    '''Sign the data with the private key and return the signature.

    :param data: The content of the wheel record file
    :param privkey: The serialized private key used to sign the data.
    :type privkey:
        cryptography.hazmat.primitives.asymmetric.dsa.DSAPrivateKey or
        cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey or
        cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey
    :rtype: bytes
    '''

    if isinstance(privkey, dsa.DSAPrivateKey):
        signature = privkey.sign(data, hashes.SHA256())
    elif isinstance(privkey, ec.EllipticCurvePrivateKey):
        signature = privkey.sign(data, ec.ECDSA(hashes.SHA256()))
    elif isinstance(privkey, rsa.RSAPrivateKey):
        signature = privkey.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    else:
        raise TypeError('invalid key type')
    return signature


# def write_signature(wheelfile, certificate, signature):
#     wf = wheel.install.WheelFile(wheelfile, append=True)
#     wf.zipfile.writestr(_signfile(wf), signature)
#     with open(certificate) as fp:
#         wf.zipfile.writestr(_certfile(wf), fp.read())
#     wf.zipfile.close()


def sign_wheel(wheelfile, certificate, privkey):
    '''Sign the wheel file with the given certificate and private key.
    If the private key is encrypted, ask for the password.

    :param str privkey: Private key file name.
    :param str certificate: Certificate file name.
    :param str wheelfile: Wheel file name.
    '''

    # XXX: check if already signed?
    with open(privkey, 'rb') as fp:
        privkey_pem = fp.read()
    try:
        key = load_pem_private_key(privkey_pem, None, backend)
    except TypeError as exc:
        import getpass
        password = getpass.getpass()
        # XXX: which encoding?
        password = password.encode('utf-8')
        key = load_pem_private_key(privkey_pem, password, backend)
    with open(wheelfile, 'a') as fp:
        wf = wheel.install.WheelFile(wheelfile, fp, append=True)
        records = wf.zipfile.read(_record(wf))
        signature = _sign(records, key)
        wf.zipfile.writestr(_signfile(wf), signature)
        with open(certificate) as fp:
            wf.zipfile.writestr(_certfile(wf), fp.read())


def _sign_wheel_cmdline(args):
    try:
        return sign_wheel(args.wheelfile, args.certificate, args.privkey)
    except (wheel.install.BadWheelFile, zipfile.BadZipfile) as exc:
        return '{0}: {1}'.format(args.wheelfile, str(exc))


def main():
    import argparse
    import os

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()
    sign_parser = subparsers.add_parser('sign')
    sign_parser.add_argument('--privkey', required=True)
    sign_parser.add_argument('--certificate', required=True)
    sign_parser.add_argument('--wheelfile', required=True)
    sign_parser.set_defaults(func=_sign_wheel_cmdline)
    verify_parser = subparsers.add_parser('verify')
    verify_parser.add_argument('--wheelfile', required=True)
    verify_parser.add_argument('--exclude-default-paths', action='store_true')
    verify_parser.add_argument(
        '--include-file',
        action='append',
        default=[],
        type=os.fsencode
    )
    verify_parser.add_argument(
        '--include-dir',
        action='append',
        default=[],
        type=os.fsencode
    )
    verify_parser.add_argument('--hostname')
    verify_parser.add_argument('--password', action='store_true')
    verify_parser.set_defaults(func=_verify_wheel_cmdline)
    args = parser.parse_args()
    return args.func(args)


if __name__ == '__main__':
    import sys
    sys.exit(main())
