#!/usr/bin/python3
# -*- coding: utf-8 -*-

#############################################################################
##                                                                         ##
## This file is part of DPAPIck                                            ##
## Windows DPAPI decryption & forensic toolkit                             ##
##                                                                         ##
##                                                                         ##
## Copyright (C) 2010, 2011 Cassidian SAS. All rights reserved.            ##
## Copyright (C) 2023       Insecurity. All rights reserved.               ##
##                                                                         ##
##  Author:  Jean-Michel Picod <jmichel.p@gmail.com>                       ##
##  Updated: Photubias <info@insecurity.be>                                ##
##                                                                         ##
## This program is distributed under GPLv3 licence (see LICENCE.txt)       ##
##                                                                         ##
#############################################################################

import setuptools

long_description = open('README.md', 'r').read()

setuptools.setup(
    name = 'dpapick3',
    version = '0.5.0',
    author = 'Tijl Deneut',
    author_email = 'info@insecurity.be',
    description = 'A native implementation of DPAPI',
    long_description = long_description,
    long_description_content_type = 'text/markdown',
    url = 'https://github.com/tijldeneut/dpapick3',
    packages = setuptools.find_packages(),
    include_package_data = True,
    zip_safe = False,
    classifiers=[
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires = '>=3.2',
    install_requires = [
        'pycryptodome',
        'python-registry',
        'pyasn1'
    ]
)
