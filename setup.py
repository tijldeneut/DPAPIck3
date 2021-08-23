#!/usr/bin/env python3
import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="dpapick3",
    version="0.2.0",
    author="Tijl Deneut",
    author_email="tijl.deneut@howest.be",
    description="A native implementation of DPAPI",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/tijldeneut/dpapick3",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.2',
    install_requires=[
        'pycryptodome',
        'python-registry'
    ]
)