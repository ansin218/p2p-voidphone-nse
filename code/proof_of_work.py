"""
    REFERENCES:
    1. https://ep2017.europython.eu/media/conference/slides/bitcoin-and-blockchain-for-pythoneers.pdf
    2. https://knnubt06oc.kuenn.co/how-to-blockchain-proof-of-work-using-python3/
"""

import string
import random
import hashlib
import time
import copy
import math
from datetime import datetime


"""
    Generates the puzzle to be solved for 
    proof-of-work validation and verfication
"""
def generate_puzzle(pow_problem):
    size = 19
    solution = ''.join(random.choice(string.ascii_lowercase +
                                   string.ascii_uppercase +
                                   string.digits)
                     for x in range(size))
    trial = pow_problem + solution
    return trial, solution


"""
    Generates the string for PoW using time value
    and tests if string ends with four 0s
"""
def create_pow(pow_problem, num_of_matches):
    found = False
    start_time = time.time()
    while found == False:
        trial, solution = generate_puzzle(pow_problem)
        attempt_01 = trial.encode('utf-8')
        sha_hashing_256 = hashlib.sha256()
        sha_hashing_256.update(attempt_01)
        final_sol = sha_hashing_256.hexdigest()
        if final_sol.endswith("0" * num_of_matches):
            time_taken = time.time() - start_time
            found = True
            return solution


"""
    Verifies the proof-of-work with the generated string
    and number of matches of 0s in the end
"""
def verify_pow(pow_problem, num_of_matches):
    found = False
    start_time = time.time()
    while found == False:
        trial, solution = generate_puzzle(pow_problem)
        attempt_01 = trial.encode('utf-8')
        sha_hashing_256 = hashlib.sha256()
        sha_hashing_256.update(attempt_01)
        final_sol = sha_hashing_256.hexdigest()
        if final_sol.endswith("0" * num_of_matches):
            time_taken = time.time() - start_time
            found = True
            return found

"""
    Calls the function for creating and verifying 
    proof-of-work; uses the string in pow_problem
"""
def pow_result():
    pow_problem = str(datetime.utcnow().replace(minute=0, second=0, microsecond=0))
    match_num = 4
    proof = create_pow(pow_problem, match_num)
    if verify_pow(pow_problem, match_num):
        print("Proof-of-Work Verified!")
    else:
        print("Could not verifiy Proof-of-Work!")


if __name__ == '__main__':
    pow_result()