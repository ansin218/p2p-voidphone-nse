import math
from datetime import datetime
from datetime import timedelta

"""
    Gets current starting time with flooding delay
"""
def get_cst_and_fd(nw_size_estimate, overlapping_bits):
    hr_in_ms = 3600000.0 
    flood_delay_in_ms = (hr_in_ms/2) - (hr_in_ms/math.pi) * (math.atan(overlapping_bits - nw_size_estimate))
    starttime = datetime.utcnow().replace(minute = 0, second = 0, microsecond = 0)
    ct_plus_fd = starttime + timedelta(milliseconds = flood_delay_in_ms)
    return ct_plus_fd

"""
    Computes processing delay of messages
"""
def compute_process_delay(send_time):
    time_difference = send_time - datetime.utcnow()
    (delay_in_min, delay_in_sec) = divmod(time_difference.total_seconds(), 60)
    delay_min_to_sec = delay_in_min * 60
    computed_time_sec = delay_min_to_sec + delay_in_sec
    return computed_time_sec


if __name__ == "__main__":
    current_time = datetime.utcnow().replace(minute = 0, second = 0, microsecond = 0)
    print(current_time)