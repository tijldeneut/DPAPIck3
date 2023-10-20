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

import dpapick3.crypto as crypto
import dpapick3.eater as eater

class DPAPIBlob(eater.DataStruct):
    """Represents a DPAPI blob"""

    def __init__(self, raw=None):
        """Constructs a DPAPIBlob. If raw is set, automatically calls
            parse().

        """
        self.version = None
        self.provider = None
        self.mkguid = None
        self.mkversion = None
        self.flags = None
        self.description = None
        self.cipherAlgo = None
        self.keyLen = 0
        self.hmac = None
        self.strong = None
        self.hashAlgo = None
        self.hashLen = 0
        self.cipherText = None
        self.salt = None
        self.blob = None
        self.sign = None
        self.cleartext = None
        self.decrypted = False
        self.signComputed = None
        eater.DataStruct.__init__(self, raw)

    def parse(self, data):
        """Parses the given data. May raise exceptions if incorrect data are
            given. You should not call this function yourself; DataStruct does

            data is a DataStruct object.
            Returns nothing.

        """
        self.version = data.eat("L")
        self.provider = "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x" % data.eat("L2H8B")

        # For HMAC computation
        blobStart = data.ofs

        self.mkversion = data.eat("L")
        self.mkguid = "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x" % data.eat("L2H8B")

        self.flags = data.eat("L")
        self.description = data.eat_length_and_string("L").decode("UTF-16LE").encode("utf-8")
        self.cipherAlgo = crypto.CryptoAlgo(data.eat("L"))
        self.keyLen = data.eat("L")
        self.salt = data.eat_length_and_string("L")
        self.strong = data.eat_length_and_string("L")
        self.hashAlgo = crypto.CryptoAlgo(data.eat("L"))
        self.hashLen = data.eat("L")
        self.hmac = data.eat_length_and_string("L")
        self.cipherText = data.eat_length_and_string("L")

        # For HMAC computation
        self.blob = data.raw[blobStart:data.ofs]
        self.sign = data.eat_length_and_string("L")

    def decrypt(self, masterkey, entropy=None, strongPassword=None, smartCardSecret=None):
        """Try to decrypt the blob. Returns True/False
        :rtype : bool
        :param masterkey: decrypted masterkey value
        :param entropy: optional entropy for decrypting the blob
        :param strongPassword: optional password for decrypting the blob
        :param smartCardSecret: MS Next Gen Crypto secret (e.g. from PIN code)
        """
        for algo in [crypto.CryptSessionKeyType1, crypto.CryptSessionKeyType2]:
            sessionkey = algo(masterkey, self.salt, self.hashAlgo, entropy=entropy, smartcardsecret=smartCardSecret, strongPassword=strongPassword)
            key = crypto.CryptDeriveKey(sessionkey, self.cipherAlgo, self.hashAlgo)
            #RC4 is a stream cipher, and so we need to call module without the mode parameter
            if self.cipherAlgo == "RC4":
              cipher =  self.cipherAlgo.module.new(key[:int(self.cipherAlgo.keyLength)],
                                                  IV=b'\x00' * int(self.cipherAlgo.ivLength))
            else:
              cipher = self.cipherAlgo.module.new(key[:int(self.cipherAlgo.keyLength)],
                                                mode=self.cipherAlgo.module.MODE_CBC,
                                                IV=b'\x00' * int(self.cipherAlgo.ivLength))
            self.cleartext = cipher.decrypt(self.cipherText)
            padding = self.cleartext[-1]
            if padding <= self.cipherAlgo.blockSize:
                self.cleartext = self.cleartext[:-padding]
            # check against provided HMAC
            self.signComputed = algo(masterkey, self.hmac, self.hashAlgo, entropy=entropy, smartcardsecret=smartCardSecret, verifBlob=self.blob)
            self.decrypted = self.signComputed == self.sign
            if self.decrypted:
                return True
        self.decrypted = False
        return self.decrypted

    def __repr__(self):
        s = ["DPAPI BLOB",
             "\n".join(("\tversion      = %(version)d",
                        "\tprovider     = %(provider)s",
                        "\tmkey         = %(mkguid)s",
                        "\tflags        = %(flags)#x",
                        "\tdescr        = %(description)s",
                        "\tcipherAlgo   = %(cipherAlgo)r",
                        "\thashAlgo     = %(hashAlgo)r")) % self.__dict__,
             "\tsalt         = %s" % self.salt.hex(),
             "\thmac         = %s" % self.hmac.hex(),
             "\tcipher       = %s" % self.cipherText.hex(),
             "\tsign         = %s" % self.sign.hex()]
        if self.signComputed is not None:
            s.append("\tsignComputed = %s" % self.signComputed.hex())
        if self.cleartext is not None:
            s.append("\tcleartext    = %r" % self.cleartext)
        return "\n".join(s)

# vim:ts=4:expandtab:sw=4
