import copy
import math
from datetime import datetime
from datetime import timedelta
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

from proof_of_work import create_pow
from proof_of_work import verify_pow
from compute_time import *
from crypto_op import CryptographicOperations
from nse_protocol_validator import ProtocolValidator 
from tcp_connect import NSEServer


"""
    Functionality to create, handle and update the message
"""
class ProtocolHandler:
    def __init__(self, path, pow_match_count):

        try:
            with open(path, 'r') as file:  
                self.hostkey = RSA.importKey(file.read())
        except IOError as io_error:
            print("\nHostkey IO Error Encountered")
            print(io_error)
        except FileNotFoundError as file_not_found_error:
            print("\nHostkey File Not Found")
            print(file_not_found_error)
        except TypeError as type_error:
            print("\nHostkey File Unknown Type")
            print(type_error)
        except IndexError as index_error:
            print("\nHostkey File Index Error")
            print(index_error)

        self.public_key_rsa = self.hostkey.publickey()
        self.public_key_string = self.public_key_rsa.exportKey(format='PEM')
        self.public_key_string = self.public_key_string.decode('utf-8')

        hashed_peer = SHA256.new()
        hash_public_key = self.public_key_string.encode('utf-8')
        hashed_peer.update(hash_public_key)

        self.identifier = hashed_peer.hexdigest()
        self.crypto_op = CryptographicOperations()
        self.pow_match_count = pow_match_count
        self.proof_of_work = create_pow(self.identifier, self.pow_match_count)
        self.current_start_time = datetime.utcnow().replace(minute=0, second=0, microsecond=0)
        self.msg = self.form_msg()  
        self.current_closest_msg = self.msg
        self.future_msgs = dict()

    
    def form_msg(self):
        start_time = datetime.utcnow().strftime("%Y-%m-%d %H:00:00")
        identifier = self.identifier
        counter = 0
        hashed = SHA256.new()
        hash_time = start_time.encode('utf-8')
        hashed.update(hash_time)
        hashed_time = hashed.hexdigest()
        hashed_time_binary = bin(int(hashed_time, 16))[2:].rjust(256, '0')
        identifier_binary = bin(int(identifier, 16))[2:].rjust(256, '0')
        hashed_time_bin_len = len(hashed_time_binary)
        while counter < hashed_time_bin_len and hashed_time_binary[counter] == identifier_binary[counter]:
            counter+=1

        dist_proximity = counter
        public_key = self.public_key_string
        pow_val = self.proof_of_work
        pow_match_count = self.pow_match_count
        sig_msg = start_time + str(dist_proximity) + public_key + pow_val
        sig_key = self.hostkey
        signature = self.crypto_op.asy_sign_msg(sig_msg, sig_key)
        protocol_validator = ProtocolValidator(start_time, dist_proximity, public_key, pow_val, signature, pow_match_count)
        return protocol_validator


    def manage_msg(self, new_msg, current_estimate):
        self.update_msg()
        current_start_time = datetime.utcnow().replace(minute=0, second=0, microsecond=0)
        msg_start_datetime = datetime.strptime(new_msg.start_time, "%Y-%m-%d %H:00:00")

        if msg_start_datetime > current_start_time:
            try:
                future_msg = self.future_msgs[new_msg.start_time]
                if new_msg.dist_proximity > future_msg.dist_proximity:
                    f_msg = self.future_msgs[new_msg.start_time]
                    f_msg = new_msg
            except KeyError as key_error:
                f_msg = self.future_msgs[new_msg.start_time]
                f_msg = new_msg
            except IOError as io_error:
                print("\nHostkey IO Error Encountered")
                print(io_error)
            return None, None  

        current_closest_proximity = self.current_closest_msg.dist_proximity
        new_proximity = new_msg.dist_proximity

        if new_proximity >= current_closest_proximity:
            self.current_closest_msg = new_msg
            processing_delay = compute_process_delay(get_cst_and_fd(current_estimate, new_proximity))
            print(new_proximity)
            print(current_closest_proximity)
            return new_msg, processing_delay  
        elif new_proximity <= current_closest_proximity:
            return self.current_closest_msg, 0  
        else:
            return None, None


    def update_msg(self):
        get_current_start_time = datetime.utcnow().replace(minute=0, second=0, microsecond=0)
        if get_current_start_time > self.current_start_time:

            self.current_start_time = get_current_start_time
            self.msg = self.form_msg()

            current_msg_time = datetime.strptime(self.current_closest_msg.start_time, "%Y-%m-%d %H:00:00")
            new_msg_time = datetime.strptime(self.msg.start_time, "%Y-%m-%d %H:00:00")
            msg_proximity = self.msg.dist_proximity
            current_proximity = self.current_closest_msg.dist_proximity

            if msg_proximity > current_proximity or new_msg_time > current_msg_time:
                self.current_closest_msg = self.msg


if __name__ == "__main__":
    nse_protocol_handler = ProtocolHandler('hostkey.pem', 4)
    future_msg = nse_protocol_handler.msg
    next_round_time = datetime.utcnow() + timedelta(hours=1)
    future_msg.start_time = next_round_time.strftime("%d-%m-%Y %H:00:00")
    nse_protocol_handler.manage_msg(future_msg, 3)
    better_future_msg = copy.copy(future_msg)
    better_future_msg.dist_proximity = 1000
    nse_protocol_handler.manage_msg(better_future_msg, 3)