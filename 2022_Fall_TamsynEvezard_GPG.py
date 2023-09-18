#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Nov 16 22:15:31 2022s

@author: tamsynevezard
"""

"""
    Program decrypts very simple GPG files and saves the plaintext contents out to a new file 
    using S2K conversion, GPG file parsing, 3DES decryption, and MD5 hashing.
"""

import sys
import hashlib
import os
import s2k
import OFB_GPG
import DES_TDES

def decrypt_GPG(textfile, password):
    """Uses textfile name and password to parse each individual packet in the encrypted file, 
    create a key, and decrypt the file."""
    
    if not os.path.exists(textfile):
        print("Textfile does not exist")
        exit(0)
    
    #path exists
    with open(textfile, 'rb') as f:
        contents = f.read()
        
    sha1 = hashlib.sha1()
    sha1.update(contents)
    hash = sha1.hexdigest()

    off = 0
    
    """Parse each individual packet"""
    
    while off < len((contents)):
        
        #examine current packet
        packet = contents[off:]
        header = packet[0]
        
        valid_mask = 0x80
        format_mask = 0x40
        old_tag_mask = 0x3c
        new_tag_mask = 0x3f
        ltype_mask = 0x03
        
        """INVALID"""
        if header & valid_mask == 0:
            print("error")
            exit(0)
            
        """VALID"""
        
        if header & format_mask == 0: # old format
            tag = (header & old_tag_mask) >> 2
            ltype = header & ltype_mask
            if ltype == 0:
                hlen = 2
                plen = packet[1]
                pdata = packet[0:hlen + plen]
            else: 
                raise ValueError("can't parse that length type yet")
            if(ltype) == 1:
                hlen = 3 # 2 octet length
                plen = int.from_bytes(packet[1:3], byteorder='big')
                pdata = packet[0:hlen + plen]
            if(ltype) == 2:
                hlen = 5 # 4 octet length
                plen = int.from_bytes(packet[1:5], byteorder='big')
                pdata = packet[0:hlen + plen]
            if(ltype) == 3:
                hlen = None
            ctb = pdata[0:1]
            ctb = DES_TDES.CORE._bytes_to_bit_array(ctb)
            s = [str(i) for i in ctb]
            b = int("".join(s), 2)
            c = hex(b)[2:].zfill(2)
            ctb = c

            print(f" off={off} ctb={ctb} tag={tag} hlen={hlen} plen={plen}")

                
        elif header & format_mask != 0: # new format

            tag = (header & new_tag_mask)
            
            temp = packet[1]
            if temp <= 191:
                hlen = 2
                plen = temp
                pdata = packet[0:hlen + plen]
            else:
                temp = int.from_bytes(packet[1:3], byteorder='big')
                if 192 < temp <= 8030:   
                    hlen = 3
                    plen = ( (packet[1] - 192) << 8) + (packet[2]) + 192
                    pdata = packet[0:hlen + plen]
                
                else:
                    temp = int.from_bytes(packet[1:6], byteorder='big')
                    if 8030 < temp:
                        hlen = 6
                        plen = (packet[2] << 24) | (packet[3] << 16) | (packet[4] << 8) | packet[5]
                        pdata = packet[0:hlen + plen]
            
            ctb = pdata[0:1]
            ctb = DES_TDES.CORE._bytes_to_bit_array(ctb)
            s = [str(i) for i in ctb]
            b = int("".join(s), 2)
            c = hex(b)[2:].zfill(2)
            ctb = c
            
            print(f" off={off} ctb={ctb} tag={tag} hlen={hlen} plen={plen} new-ctb")
            
           
            
        """Get settings for string to key calculation and decryption"""
        
        #key length
        sym_alg = packet[3]
        
        if(sym_alg == 2):
            key_length = 24
            
        s2k_mode = packet[4]
        
        hash_algorithm = packet[5]
            
        if(tag == 3):
            packet_type = "symkey enc packet"

            print(f":{packet_type}:")
            
            session_key = s2k.CORE.calculate_s2k(password, s2k_mode, key_length, hash_algorithm)
            off += hlen + plen
            
            
        elif(tag == 18):
            packet_type = "encrypted data packet"
            print(f":{packet_type}:")

            plaintext = OFB_GPG.test_decrypt(textfile, session_key, "OFB", b"\x00\x00\x00\x00\x00\x00\x00\x00")

            contents = plaintext
            sha1 = hashlib.sha1()
            sha1.update(plaintext[:-20])
            calculated_hash = sha1.hexdigest()
            #print(f"SHA-1 ({textfile}) = {calculated_hash}")

            off = 10

            
        elif(tag == 11):
            packet_type = "literal data packet"
            print(f":{packet_type}:")
            pdata = packet[hlen:hlen+plen]
            b_or_t = pdata[0]
            l_filename = pdata[1]
            filename = pdata[2:2+l_filename]
            timestamp = pdata[2+l_filename:2+l_filename+4]
            section = pdata[2+l_filename+4:]
            print(filename)
            print(section)
            
            off += hlen + plen
            
        elif(tag == 19):
            packet_type = "modification detection packet"
            print(f":{packet_type}:")
            
            pdata = packet[hlen:hlen+plen]
            hash = pdata.hex()

            print(f"SHA-1 converted ({textfile}) = {hash}")
            if hash == calculated_hash:
                print("Good: File has *not* been modified")
            else:
                print("WARNING! HASHES DON'T MATCH: FILE HAS BEEN MODIFIED")

            off += hlen + plen
            

if __name__ == "__main__":
    #if(len(sys.argv) < 2):
    #    print("Help: not enough arguments given: please input textfile & password")
    
    #textfile = bytes(sys.argv[1], 'utf-8')
    textfile = "test.txt.gpg"
    #password = bytes(sys.argv[2], 'utf-8')
    password = b"test"
    decrypt_GPG(textfile, password)
    