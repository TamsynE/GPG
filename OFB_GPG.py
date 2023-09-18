#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Nov 15 12:39:16 2022

@author: tamsynevezard
"""

from DES_TDES import TDES
from DES_TDES import CORE
import DES_TDES


def test_decrypt(textfile, key, mode, iv):
    """"Decrypts textfile using the TDES OFB mode with specificed key, and initialization vector - produces plaintext"""
    
    with open(textfile, 'rb') as f:
        contents = f.read()
    textfile = contents[9:]
    
    my_obj = TDES(key, mode, iv)
    b1 = my_obj.decrypt(textfile[0:8])
    #print(f'block1: {b1.hex()}')

    my_obj2 = TDES(key, mode, iv = textfile[0:8])
    b2 = my_obj2.decrypt(textfile[8:16])
    #print(f'block2: {b2.hex()}')
    
    plaintext = b1 + b2
    
    iv = textfile[8:16]
    for block in DES_TDES.CORE._nsplit(textfile[16:], 8):
        
        d = TDES(key, mode, iv = iv)
        b = d.decrypt(block)
        iv = block
        plaintext += b
    return plaintext
    
def unit_testGPG():
    
    textfile = "test.txt.gpg"
    out_data = b"\x1c\x91\x73\x94\xba\xfb\x3c\x30\x3c\x30\xac\x26\x62\x09\x74\x65" + \
           b"\x73\x74\x31\x2e\x74\x78\x74\x5e" + \
           b"\xc5\xf7\x32\x4c\x69\x76\x65\x20" + \
           b"\x66\x72\x65\x65\x20\x6f\x72\x20" + \
           b"\x64\x69\x65\x20\x68\x61\x72\x64" + \
           b"\x0d\x0a\xd3\x14\x7c\x2e\x86\x89" + \
           b"\x7a\x42\x58\xed\x06\x53\x9f\x15" + \
           b"\xcc\xca\x7e\x7b\x37\x28\x5f\x3c"
    
    s2k_m0_key = b'\x09\x8f\x6b\xcd\x46\x21\xd3\x73\xca\xde\x4e\x83' + \
                 b'\x26\x27\xb4\xf6\x5f\x8f\x8e\x05\xef\xdc\x22\xe8'
    iv1 = b"\x00\x00\x00\x00\x00\x00\x00\x00"
    mode1 = "OFB" 
    
    output = test_decrypt(textfile = textfile, key = s2k_m0_key, mode = mode1, iv = iv1)

    
    assert output == out_data
    print("ALL TESTS PASSED")
    
if __name__ == "__main__":

    unit_testGPG()

