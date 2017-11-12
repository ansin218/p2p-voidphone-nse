import copy
import math
import string
from datetime import datetime
from datetime import timedelta
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

from proof_of_work import create_pow
from proof_of_work import verify_pow
from compute_time import *
from crypto_op import CryptographicOperations
from tcp_connect import NSEServer

"""
    Functionality to validate everything required to run the NSE according to the specifications
    Validates based on type of content of variables, time, proof-of-work, signature
"""
class ProtocolValidator:
    def __init__(self, start_time, dist_proximity, public_key, pow_val, signature, pow_match_count):
        self.validate = True

        try:
            self.start_time = str(start_time)
            self.dist_proximity = dist_proximity
            self.public_key = public_key
            self.pow_val = pow_val
            self.signature = signature
            self.pow_match_count = pow_match_count

        except KeyError as key_error:
            print("Key Error! Validating value to False!")
            print(key_error)
            return False

        if self.validate == False:
            print("Invalid Protocol Message!")

        self.validate_nse(pow_match_count)


    def validate_nse(self, pow_match_count):
        if not isinstance(self.start_time, str) or not isinstance(self.dist_proximity, int) or not isinstance(self.public_key, str) or not isinstance(self.pow_val, str) or not isinstance(self.signature, bytes):
            self.validate = False
            if not isinstance(self.start_time, str): 
                print("Invalid Type of Start Time")
            if not isinstance(self.dist_proximity, int):
                print("Invalid Type of Distance Proximity")
            if not isinstance(self.public_key, str):
                print("Invalid Type of Public Key")
            if not isinstance(self.pow_val, str):
                print("Invalid Type of Proof-of-Work Value")
            if not isinstance(self.signature, bool):
                print("Invalid Type of Signature")

        print("\nPublic Key: ", self.public_key)
        counter = 0
        start_time = self.start_time
        hashed = SHA256.new()
        hash_public_key = self.public_key.encode('utf-8')
        hashed.update(hash_public_key)
        identity = hashed.hexdigest()
        crypto_op = CryptographicOperations()
        current_start_time = datetime.utcnow().replace(minute=0, second=0, microsecond=0)
        msg_date_time = datetime.strptime(self.start_time, "%Y-%m-%d %H:00:00")
        
        if msg_date_time < current_start_time:
            self.validate = False  
        
        print("\nIdentity: ", identity)
        print("PoW Value: ", self.pow_val)
        pow_verification = verify_pow(identity, self.pow_match_count)
        print("PoW Result: ", pow_verification)
        if not pow_verification:
            self.validate = False

        pow_solution = self.start_time + str(self.dist_proximity) + self.public_key + self.pow_val
        signature_verification = crypto_op.verify_signature(self.signature, pow_solution)
        print("Signature Result: ", signature_verification)
        if not signature_verification:
            self.validate = False

        prox_hashed = SHA256.new()
        hash_time = start_time.encode('utf-8')
        prox_hashed.update(hash_time)
        hashed_time = prox_hashed.hexdigest()
        hashed_time_binary = bin(int(hashed_time, 16))[2:].rjust(256, '0')
        identifier_binary = bin(int(identity, 16))[2:].rjust(256, '0')
        hashed_time_bin_len = len(hashed_time_binary)
        while counter < hashed_time_bin_len and hashed_time_binary[counter] == identifier_binary[counter]:
            counter += 1
        
        current_dist_proximity = counter
        if self.dist_proximity != current_dist_proximity:
            self.validate = False

        print("\nIdentity verified \nProof-of-Work Verified! \nKey Verified! \nSignature Verified!")
        print("\nPRESS CTRL + C TO HALT THE PROGRAM")