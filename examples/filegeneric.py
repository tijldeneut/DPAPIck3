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

from dpapick3 import probe, blob, masterkey

import argparse, base64, binascii

class GenericDecryptor(probe.DPAPIProbe):

    def parse(self, data):
        self.dpapiblob = blob.DPAPIBlob(data.remain())

    def __getattr__(self, name):
        return getattr(self.dpapiblob, name)

    def __repr__(self):
        s = ["Generic password decryptor"]
        if self.dpapiblob is not None and self.dpapiblob.decrypted:
            s.append("        password = %s" % self.cleartext)
        s.append("    %r" % self.dpapiblob)
        return "\n".join(s)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--sid", metavar="SID", dest="sid")
    parser.add_argument("--masterkey", required=True, metavar="DIRECTORY", dest="masterkeydir")
    parser.add_argument("--credhist", required=False, metavar="FILE", dest="credhist")
    parser.add_argument("--password", required=False, metavar="PASSWORD", dest="password")
    parser.add_argument("--hash", required=False, metavar="PASSWORD", dest="hash")
    parser.add_argument("--inputfile", required=False, metavar="FILE", dest="inputfile")
    parser.add_argument("--base64file", required=False, metavar="FILE", dest="b64file")
    parser.add_argument("--syskey", required=False, metavar="PASSWORD", dest="syskey", help="DPAPI_SYSTEM string. 01000000..., run lsasecrets.py")
    parser.add_argument("--pkey", required=False, help="Private domain KEY", dest="pkey")
    parser.add_argument("--entropy", required=False, help="Decrypt entropy, 0xaabb... or Base64", dest="entropy")
    parser.add_argument("--debug", required=False, action="store_true",dest="debug")
                      #help="lines with base64-encoded password blobs")

    options = parser.parse_args()

    entropy = None
    decrn = 0
    if options.entropy:
        if options.entropy[0:2] == "0x":
            try:
                entropy=binascii.unhexlify(options.entropy[2:])
            except:
                print("Error decoding entropy")
        else:
            try:
                entropy = base64.b64decode(options.entropy)
                print("Using entropy")
            except:
                print("Error decoding entropy")

    if options.masterkeydir and options.credhist != None:
        mkp = masterkey.MasterKeyPool()
        mkp.loadDirectory(options.masterkeydir)
        mkp.addCredhistFile(options.sid, options.credhist)

    if options.masterkeydir and options.pkey:
        mkp = masterkey.MasterKeyPool()
        mkp.loadDirectory(options.masterkeydir)
        decrn = mkp.try_domain(options.pkey)
        if decrn > 0:
            print("Decrypted: "+str(decrn))
            if options.debug:
                for mkl in mkp.keys.values(): #mkl - list with mk, mkbackup, mkdomain
                    for mk in mkl:
                        print(mk.guid)

    if options.masterkeydir and options.password and options.sid:
        mkp = masterkey.MasterKeyPool()
        mkp.loadDirectory(options.masterkeydir)
        decrn = mkp.try_credential(options.sid,options.password)
        print("Decrypted masterkeys: "+str(decrn))

    if options.masterkeydir and options.hash and options.sid:
        mkp = masterkey.MasterKeyPool()
        mkp.loadDirectory(options.masterkeydir)
        options.hash = binascii.unhexlify(options.hash)
        decrn = mkp.try_credential_hash(options.sid, options.hash)
        print("Decrypted masterkeys: " + str(decrn))

    if options.masterkeydir and options.syskey:
        mkp = masterkey.MasterKeyPool()
        mkp.loadDirectory(options.masterkeydir)
        mkp.addSystemCredential(binascii.unhexlify(options.syskey))
        decrn = mkp.try_credential_hash(None, None)
        print("Decrypted masterkeys: " + str(decrn))

    if decrn == 0:
        print("No decrypted masterkeys ! ")
        print("Exiting..")
        exit()

    if options.inputfile:
        with open(options.inputfile, "rb") as file:
            data=file.read()
        probe = GenericDecryptor(data)
        #if probe.try_decrypt_with_password(options.password, mkp, options.sid):
        if probe.try_decrypt_with_hash(options.hash, mkp, options.sid, entropy=entropy):
            print("Decrypted clear: %s" % probe.cleartext)
            print("Decrypted hex: %s" % binascii.hexlify(probe.cleartext))

    if options.b64file:
        with open(options.b64file, 'r') as f:
            lines = f.readlines()

        for line in lines:
            dline = base64.b64decode(line)
            probe = GenericDecryptor(dline)
            if options.debug: print(probe)

            if probe.try_decrypt_with_password(options.password, mkp, options.sid, entropy=entropy):
                print("Decrypted clear: %s" % probe.cleartext)
                print("Decrypted hex: %s" % binascii.hexlify(probe.cleartext))

# vim:ts=4:expandtab:sw=4