#!/usr/bin/python3
# -*- coding: utf-8 -*-

#############################################################################
##                                                                         ##
## This file is part of DPAPIck3                                           ##
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

import dpapick3.registry as registry
import os
from datetime import datetime
from optparse import OptionParser

if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("--system", metavar="HIVE", dest="system", default=os.path.join('Windows','System32','config','SYSTEM'))
    parser.add_option("--security", metavar="HIVE", dest="security", default=os.path.join('Windows','System32','config','SECURITY'))
    parser.add_option("--secret", metavar="NAME", dest="secret")
    parser.add_option("--hex", default=False, dest="hexencode", action="store_true")
    parser.add_option("--unicode", default=False, dest="unicode", action="store_true")
    
    (options, args) = parser.parse_args()

    reg = registry.Regedit()
    secrets = reg.get_lsa_secrets(options.security, options.system)
    if options.secret is not None: 
        if secrets.get(options.secret) is not None:
            if options.hexencode:
                print((secrets[options.secret]['CurrVal'].hex()))
                print((secrets[options.secret]['OldVal'].hex()))
            else:
                if options.unicode:
                    print((bytes.fromhex(secrets[options.secret]['CurrVal'].hex()).decode('utf-16le')))
                    print((bytes.fromhex(secrets[options.secret]['OldVal'].hex()).decode('utf-16le')))
                else:
                    print((secrets[options.secret]['CurrVal']))
                    print((secrets[options.secret]['OldVal']))
    else:
        for i in list(secrets.keys()):
            for k, v in list(secrets[i].items()):
                if k in ('CurrVal', 'OldVal'):
                    ## String
                    data = v
                    if options.unicode:
                        try: data = v.decode('utf-16le')
                        except: 
                            if options.hexencode: data = v.hex()
                    elif options.hexencode: data = v.hex()
                    print(('\t'.join([i, k, '\t'+str(data)])))
                    #print(('\t'.join([i, k, v.hex() if options.hexencode else str(v)])))
                elif k in ('OupdTime', 'CupdTime'):
                    ## Timestamp
                    print(('\t'.join([i, k, datetime.utcfromtimestamp(v).isoformat(' ')])))

# vim:ts=4:expandtab:sw=4
