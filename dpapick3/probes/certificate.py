#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#############################################################################
##                                                                         ##
## This file is part of DPAPIck                                            ##
## Windows DPAPI decryption & forensic toolkit                             ##
##                                                                         ##
##                                                                         ##
## Copyright (C) 2010, 2011 Cassidian SAS. All rights reserved.            ##
## Copyright (C) 2021       Howest. All rights reserved.                   ##
##                                                                         ##
##  Author:  Jean-Michel Picod <jmichel.p@gmail.com>                       ##
##  Updated: Photubias <tijl.deneut@howest.be>                             ##
##                                                                         ##
## This program is distributed under GPLv3 licence (see LICENCE.txt)       ##
##                                                                         ##
#############################################################################

from dpapick3 import probe, blob

try:
    from pyasn1.type import univ, namedtype
    from pyasn1.codec.der import encoder
except:
    raise Exception("PyASN1 is required.")

class PrivateKeyBlob(probe.DPAPIProbe):
    """This class represents a RSA private key file as used by Internet Explorer
    and EFS certificates.
    They are located under %APPDATA%\\Microsoft\\Crypto\\RSA
    If one requires to have the full PKCS#12 certificate, the description field
    may be used to locate the corresponding certificate file, located under
    %APPDATA%\\Microsoft\\SystemCertificates\\My\\Certificates
    This description field is encoded in UTF-16LE format at the beginning of the
    certificate file.
    """

    class RSAHeader(probe.DPAPIProbe):
        """This subclass represents the header + modulus, beginning with the
        magic value "RSA1"
        """
        def parse(self, data):
            self.magic = data.eat("4s")  # RSA1
            self.len1 = data.eat("L")  # e.g. 0x108 (264)
            self.bitlength = data.eat("L")  # e.g. 0x400 (1024) or 0x800 (2048)
            self.unk = data.eat("L")  # e.g. 0x7F (127) or 0xFF (255)
            self.pubexp = data.eat("L")  # e.g. 0x00010001 (65537)
            self.data = data.eat("%is" % self.len1)
            self.data = self.data.strip(b'\x00') # strip NULL-bytes

        def __repr__(self):
            s = ["RSA header",
                 "\tmagic     = %s" % self.magic,
                 "\tbitlength = %d" % self.bitlength,
                 "\tunknown   = %x" % self.unk,
                 "\tpubexp    = %d" % self.pubexp,
                 "\tdata      = %s" % self.data.hex()]
            return "\n".join(s)

    class RSAKey(probe.DPAPIProbe):
        """This subclass represents the RSA privatekey BLOB, beginning with the
        magic value "RSA2"
        """

        class RSAKeyASN1(univ.Sequence):
            """subclass for ASN.1 sequence representing the RSA key pair.
            Mainly useful to export the key to OpenSSL
            """
            componentType = namedtype.NamedTypes(
                namedtype.NamedType('version', univ.Integer()),
                namedtype.NamedType('modulus', univ.Integer()),
                namedtype.NamedType('pubexpo', univ.Integer()),
                namedtype.NamedType('privexpo', univ.Integer()),
                namedtype.NamedType('prime1', univ.Integer()),
                namedtype.NamedType('prime2', univ.Integer()),
                namedtype.NamedType('exponent1', univ.Integer()),
                namedtype.NamedType('exponent2', univ.Integer()),
                namedtype.NamedType('coefficient', univ.Integer())
            )

        def parse(self, data):
            self.magic = data.eat("4s")  # RSA2
            len1 = data.eat("L")
            self.bitlength = data.eat("L")
            chunk = int(self.bitlength / 16)
            self.unk = data.eat("L")
            self.pubexp = data.eat("L")
            self.modulus = data.eat("%is" % len1)[:2 * chunk]
            self.prime1 = data.eat("%is" % (len1 / 2))[:chunk]
            self.prime2 = data.eat("%is" % (len1 / 2))[:chunk]
            self.exponent1 = data.eat("%is" % (len1 / 2))[:chunk]
            self.exponent2 = data.eat("%is" % (len1 / 2))[:chunk]
            self.coefficient = data.eat("%is" % (len1 / 2))[:chunk]
            self.privExponent = data.eat("%is" % len1)[:2 * chunk]
            self.asn1 = self.RSAKeyASN1()
            #ll = lambda x: long(x[::-1].hex(), 16)
            ll = lambda x: int(x[::-1].hex(), 16)
            self.asn1.setComponentByName('version', 0)
            self.asn1.setComponentByName('modulus', ll(self.modulus))
            self.asn1.setComponentByName('pubexpo', self.pubexp)
            self.asn1.setComponentByName('privexpo', ll(self.privExponent))
            self.asn1.setComponentByName('prime1', ll(self.prime1))
            self.asn1.setComponentByName('prime2', ll(self.prime2))
            self.asn1.setComponentByName('exponent1', ll(self.exponent1))
            self.asn1.setComponentByName('exponent2', ll(self.exponent2))
            self.asn1.setComponentByName('coefficient', ll(self.coefficient))

        def __repr__(self):
            s = ["RSA key pair",
                 "\tPublic exponent = %d" % self.pubexp,
                 "\tModulus (n)     = %s" % self.modulus.hex(),
                 "\tPrime 1 (p)     = %s" % self.prime1.hex(),
                 "\tPrime 2 (q)     = %s" % self.prime2.hex(),
                 "\tExponent 1      = %s" % self.exponent1.hex(),
                 "\tExponent 2      = %s" % self.exponent2.hex(),
                 "\tCoefficient     = %s" % self.coefficient.hex(),
                 "\tPrivate exponent= %s" % self.privExponent.hex()]
            return "\n".join(s)

        def export(self):
            """This functions exports the RSA key pair in PEM format"""
            import base64
            s = ['-----BEGIN RSA PRIVATE KEY-----']
            text = base64.b64encode(encoder.encode(self.asn1)).decode()
            s.append(text.rstrip('\n'))
            s.append('-----END RSA PRIVATE KEY-----')
            return '\n'.join(s)

    class RSAPrivKey(probe.DPAPIProbe):
        """Internal use. This represents the DPAPI BLOB containing the RSA
        key pair"""
        def parse(self, data):
            self.dpapiblob = blob.DPAPIBlob(data.remain())

        def postprocess(self, **k):
            self.clearKey = PrivateKeyBlob.RSAKey(self.dpapiblob.cleartext)

        def export(self):
            if self.clearKey is None:
                return ""
            return self.clearKey.export()

        def __repr__(self):
            s = ["RSA Private Key Blob"]
            if self.entropy:
                s.append("entropy = %s" % self.entropy.hex())
            if hasattr(self, "strong"):
                s.append("strong = %s" % self.strong.hex())
            if self.dpapiblob.decrypted:
                s.append(repr(self.clearKey))
            s.append(repr(self.dpapiblob))
            return "\n".join(s)

    class RSAFlags(probe.DPAPIProbe):
        """This subclass represents the export flags BLOB"""
        def parse(self, data):
            self.dpapiblob = blob.DPAPIBlob(data.remain())

        def preprocess(self, **k):
            self.entropy = b"Hj1diQ6kpUx7VC4m\0"
            if hasattr(k, 'strong'):
                self.strong = k['strong']

        def __repr__(self):
            s = ["Export Flags"]
            s.append("entropy = %s" % self.entropy)
            if hasattr(self, "strong"):
                s.append("strong = %s" % self.strong.encode("hex"))
            s.append("%r" % self.dpapiblob)
            return "\n".join(s)

    def parse(self, data):
        self.version = data.eat("L")
        data.eat("L")  # NULL
        self.descrLen = data.eat("L")
        sigheadlen, sigprivkeylen = data.eat("2L")
        headerlen = data.eat("L")
        privkeylen = data.eat("L")
        self.crcLen = data.eat("L")
        sigflagslen = data.eat("L")
        flagslen = data.eat("L")

        """Follow 3 if...  Added by user4 for parsing t15-certs and private keys"""
        if headerlen == 0:
            headerlen = sigheadlen
            sigheadlen = 0
        if privkeylen == 0:
            privkeylen = sigprivkeylen
            sigprivkeylen = 0
        if flagslen == 0:
            flagslen = sigflagslen
            sigflagslen = 0


        self.description = data.eat("%ds" % self.descrLen)
        self.description = self.description.strip(b'\x00')
        self.crc = data.eat("%ds" % self.crcLen)

        # Signature key comes first
        self.sigHeader = None
        if sigheadlen > 0:
            self.sigHeader = self.RSAHeader()
            self.sigHeader.parse(data.eat_sub(sigheadlen))

        self.sigPrivateKey = None
        if sigprivkeylen > 0:
            self.sigPrivateKey = self.RSAPrivKey()
            self.sigPrivateKey.parse(data.eat_sub(sigprivkeylen))

        self.sigFlags = None
        if sigflagslen > 0:
            self.sigFlags = self.RSAFlags()
            self.sigFlags.parse(data.eat_sub(sigflagslen))

        # Then export key
        self.header = None
        if headerlen > 0:
            self.header = self.RSAHeader()
            self.header.parse(data.eat_sub(headerlen))

        self.privateKey = None
        if privkeylen > 0:
            self.privateKey = self.RSAPrivKey()
            self.privateKey.parse(data.eat_sub(privkeylen))

        self.flags = None
        if flagslen > 0:
            self.flags = self.RSAFlags()
            self.flags.parse(data.eat_sub(flagslen))

    def try_decrypt_with_hash(self, h, mkp, sid, **k):
        if not self.flags:
            return False
        if not self.privateKey:
            return False
        if self.flags.try_decrypt_with_hash(h, mkp, sid, **k):
            self.privateKey.entropy = self.flags.cleartext
            return self.privateKey.try_decrypt_with_hash(h, mkp, sid, **k)
        return False

    def try_decrypt_with_password(self, password, mkp, sid, **k):
        if not self.flags:
            return False
        if not self.privateKey:
            return False
        if self.flags.try_decrypt_with_password(password, mkp, sid, **k):
            self.privateKey.entropy = self.flags.cleartext
            return self.privateKey.try_decrypt_with_password(password, mkp, sid, **k)
        return False

    def export(self):
        """This functions encodes the RSA key pair in PEM format. Simply calls the same function on the key blob."""
        if self.privateKey:
            return self.privateKey.export()
        return ''

    def __repr__(self):
        s = ["Microsoft Certificate",
             "\tdescr: %s" % self.description]
        if self.header is not None:
            s.append("+  %r" % self.header)
        if self.privateKey is not None:
            s.append("+  %r" % self.privateKey)
        if self.flags is not None:
            s.append("+  %r" % self.flags)
        return "\n".join(s)

class Cert(probe.DPAPIProbe):
    PROP_PROVIDER = 2
    PROP_CERTIFICATE = 0x20

    PROPS = {2: "Provider", 3: "SHA-1", 4: "MD5", 15: "Signature hash",
             20: "Key identifier", 25: "Subject MD5 hash",
             69: "Backed up", 92: "Pubkey bitlength", 32: "ASN.1 certificate"}

    class CertProvider(probe.DPAPIProbe):
        def parse(self, data):
            raw = data.remain()
            ofs_keyname, ofs_provider = data.eat("2L")
            self.provider_type = data.eat("L")
            self.flags = data.eat("L")
            self.nb_params = data.eat("L")
            ofs_params = data.eat("L")
            self.key_specs = data.eat("L")
            self.keyname = raw[ofs_keyname:]
            end = self.keyname.find(b'\x00\x00\x00')
            if end & 1: end += 1
            self.keyname = self.keyname[:end].decode('UTF-16LE').rstrip('\x00')
            self.provider = raw[ofs_provider:]
            end = self.provider.find(b'\x00\x00\x00')
            if end & 1: end += 1
            self.provider = self.provider[:end].decode('UTF-16LE').rstrip('\x00')

        def __str__(self, indent=''):
            rv = ['%s+ Cert Provider' % indent]
            rv.append('%s  - Key name: %s' % (indent, self.keyname))
            rv.append('%s  - Provider: %s' % (indent, self.provider))
            return '\n'.join(rv)


    def parse(self, data):
        self.props = {}
        while data:
            cert_id, n, size = data.eat("3L")
            self.props[cert_id] = []
            for _ in range(n):
                if cert_id == self.PROP_PROVIDER:
                    provider = self.CertProvider()
                    provider.parse(data.eat_sub(size))
                    self.props[cert_id].append(provider)
                    self.name = provider.keyname
                elif cert_id == self.PROP_CERTIFICATE:
                    self.certificate = data.eat_string(size)
                else:
                    self.props[cert_id].append(data.eat_string(size))

    def __str__(self):
        rv = ["+ Microsoft Certificate"]
        for k, v in self.props.items():
            rv.append("  + %s (%d)" % (self.PROPS.get(k, "Unknown"), k))
            for p in v:
                if isinstance(p, str) or isinstance(p, bytes): rv.append('     - %s' % p.hex())
                else: rv.append(str(p))
        return '\n'.join(rv)

# vim:ts=4:expandtab:sw=4
