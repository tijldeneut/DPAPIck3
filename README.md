# DPAPIck3
OVERVIEW
========
DPAPIck3 is a python3 toolkit to provide a platform-independant implementation
of Microsoft's cryptography subsytem called DPAPI (Data Protection API).

It can be used either as a library or as a standalone tool.

It is also the first open-source tool that allows decryption of DPAPI
structures in an offline way and, moreover, from another plateform than
Windows.

REQUIREMENTS
------------
This application has been developped and tested on python 3.9.

pycryptodome is required to provide all the requireds algorithms.
Furthermore only python-registry for some scripts
* python-registry
* pycryptodome

AUTHOR
------
DPAPIck3 is written by Jean-Michel Picod (jean-michel.picod@cassidian.com)
with the help from Ivan Fontarensky (ivan.fontarensky@cassidian.com)
who work for the Cyber Security Center of Cassidian, an EADS company,
and Elie Bursztein (dpapi@elie.im)
And adjusted for Python3 and Windows 10 by Tijl Deneut (tijl.deneut@howest.be)
for the IC4 Research Group (www.ic4.be)