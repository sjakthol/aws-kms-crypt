# Based on https://github.com/pypa/sampleproject/blob/master/setup.py

from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()


setup(
    name='aws-kms-crypt',
    version='0.0.3',

    description='Utility for encrypting and decrypting secrets with the AWS KMS service',
    long_description=long_description,

    author='Sami Jaktholm',
    author_email='sjakthol@outlook.com',

    keywords='aws kms secrets encrypt decrypt tool',
    license='MIT',
    url='https://github.com/sjakthol/aws-kms-crypt',

    # https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Topic :: Security :: Cryptography',
    ],


    packages=find_packages(exclude=['tests']),
    install_requires=['boto3', 'pycrypto'],
)
