# Copyright (C) 2016 Marco Giusti
# vim: sts=4:sw=4:et

from setuptools import setup


def read(filename):
    with open(filename) as fp:
        return fp.read()


setup(
    name='wheel_sign',
    version='0.3',
    author='Marco Giusti',
    author_email='marco.giusti@posteo.de',
    description='Sign and verify wheel files using x509 certificates',
    long_description=read('README'),
    license='MIT',
    url='https://github.com/marcogiusti/wheel_sign',
    py_modules=['wheel_sign'],
    install_requires=[
        'cryptography >= 2.1.4',
        'service_identity >= 17.0.0',
        'wheel >= 0.24'
    ],
    extras_require={
        'dev': [
            'pyflakes',
            'pycodestyle',
            'tox',
            'coverage'
        ]
    },
    entry_points={
        'console_scripts': [
            'wheel_sign = wheel_sign:main'
            ]
        }
)
