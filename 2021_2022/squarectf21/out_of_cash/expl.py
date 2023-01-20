#!/usr/bin/env python3.9
# -*- coding: utf-8 -*-

from rootkit import *
import os
import time

# Set up pwntools for the correct architecture
exe  = context.binary = ELF('./out-of-cash')
host = args.HOST or 'challenges.2021.squarectf.com'
port = int(args.PORT or 7004)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

gdbscript = '''
b *main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start()

R = Rootkit()
payload = R.Exploit()

io.interactive()

"""

'Application Cryptogram'
'Application Currency Code'
'Application Currency Exponent'
'Application Discretionary Data'
'Application Effective Date'
'Application Expiration Date'
'Application File Locator (AFL)'
'Application Identifier (AID) - card'
'Application Interchange Profile'
'Application Label'
'Application Preferred Name'
'Application Primary Account Number (PAN)'
'Application Primary Account Number (PAN) Sequence Number'
'Application Priority Indicator'
'Application Reference Currency'
'Application Reference Currency Exponent'
'Application Template'
'Application Transaction Counter (ATC)'
'Application Usage Control'
'Application Version Number'
'Bank Identifier Code (BIC)'
'Card Risk Management Data Object List 1 (CDOL1)'
'Card Risk Management Data Object List 2 (CDOL2)'
'Cardholder Name'
'Cardholder Name Extended'
'Cardholder Verification Method (CVM) List'
'Certification Authority Public Key Index'
'Cryptogram Information Data'
'Data Authentication Code'
'Dedicated File (DF) Name'
'Directory Definition File (DDF) Name'
'Directory Discretionary Template'
'Dynamic Data Authentication Data Object List (DDOL)'
'File Control Information (FCI) Issuer Discretionary Data'
'File Control Information (FCI) Proprietary Template'
'File Control Information (FCI) Template'
'ICC Dynamic Number'
'Integrated Circuit Card (ICC) PIN Encipherment Public Key Certificate'
'Integrated Circuit Card (ICC) PIN Encipherment Public Key Exponent'
'Integrated Circuit Card (ICC) PIN Encipherment Public Key Remainder'
'Integrated Circuit Card (ICC) Public Key Certificate'
'Integrated Circuit Card (ICC) Public Key Exponent'
'Integrated Circuit Card (ICC) Public Key Remainder'
'International Bank Account Number (IBAN)'
'Issuer Action Code - Default'
'Issuer Action Code - Denial'
'Issuer Action Code - Online'
'Issuer Application Data'
'Issuer Code Table Index'
'Issuer Country Code'
'Issuer Country Code (alpha2 format)'
'Issuer Country Code (alpha3 format)'
'Issuer Identification Number (IIN)'
'Issuer Public Key Certificate'
'Issuer Public Key Exponent'
'Issuer Public Key Remainder'
'Issuer URL'
'Language Preference'
'Last Online Application Transaction Counter (ATC) Register'
'Log Entry'
'Log Format'
'Lower Consecutive Offline Limit'
'Personal Identification Number (PIN) Try Counter'
'Processing Options Data Object List (PDOL)'
'READ RECORD Response Message Template'
'Response Message Template Format 1'
'Response Message Template Format 2'
'Service Code'
'Short File Identifier (SFI)'
'Signed Dynamic Application Data'
'Signed Static Application Data'
'Static Data Authentication Tag List'
'Track 1 Discretionary Data'
'Track 2 Discretionary Data'
'Track 2 Equivalent Data'
'Transaction Certificate Data Object List (TDOL)'
'Upper Consecutive Offline Limit'


"""