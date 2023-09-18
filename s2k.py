#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Nov  2 16:06:22 2022

@author: tamsynevezard
"""
import hashlib

class CORE:
    def calculate_s2k(password, s2k_mode, key_length, hash_algorithm): # hash_alg as an ID number, TDES e.g. keylength would be 24, AES 128 - 16 bytes
        """ Generates an encryption key from a passphrase using the given parameters.
            The key_length parameter will depend on which encryption algorithm this key
            will be used for. For instance, the Triple DES algorithm requires a 24 byte key.
        """
        if s2k_mode == 0:
            
            key = b""
            counter = 0
            used_bytes = 0
            while used_bytes < key_length:
                # add zeros with counters
                if hash_algorithm == 1:

                    hashobj = hashlib.md5()
                elif hash_algorithm == 3:
                    hashobj = hashlib.sha1()
                    
                pad = b"\x00" * counter
                hashobj.update(pad + password)
                hash = hashobj.digest()
                key += hash
                counter += 1
                #end of loop
                used_bytes += len(hash)
            return key[:key_length]
            

        elif s2k_mode == 1 or s2k_mode ==3:
            raise ValueError(f"S2K modes 1 and 3 are not implemented")
        elif s2k_mode == 2:
            raise ValueError(f"S2K mode 2 does not exist");
        else:
            raise ValueError(f"Invalid S2K mode '{s2k_mode}'")
            
    def unit_test():
        s2k_m0_key = b'\x09\x8f\x6b\xcd\x46\x21\xd3\x73\xca\xde\x4e\x83' + \
                     b'\x26\x27\xb4\xf6\x5f\x8f\x8e\x05\xef\xdc\x22\xe8'

        password = b"test"
        symkey1 = CORE.calculate_s2k(password, 0, 24, 1)
        
        assert symkey1 == s2k_m0_key
        
        print("ALL UNIT TESTS PASSED")

if __name__ == "__main__":
    
    CORE.unit_test()

              