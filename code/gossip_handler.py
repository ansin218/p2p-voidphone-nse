import struct
import statistics
import sys
import asyncio
import asyncio.streams
import copy
import math
from datetime import datetime
from datetime import timedelta
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

from proof_of_work import create_pow
from proof_of_work import verify_pow
from nse_protocol_handler import ProtocolHandler 
from nse_protocol_validator import ProtocolValidator 
from tcp_connect import NSEServer


"""
    Socket definition function called from main.py file
    Consists of all the parameters passed from the config.ini file
    Consists of different functions to listen and respond to gossip modules
"""
def define_sockets(nse_hostkey_path, n_api_addr_address, n_api_addr_port, g_api_addr_address, g_api_addr_port, nse_history_length, nse_standard_deviation):

    subscriptions = set() 
    estimated_peer_count = 0.0
    estimated_standard_deviation = 0.0
    nse_history_length = 5
    standard_deviation_period = 30  
    nse_estimation_history = []
    pow_match_count = 4


    def gossip_handler():

        """
            Function for Gossip to notify
            Gossip which message types are valid and hence should be propagated further (project specification)
            Packing format: !, network (= big-endian),  standard, 4 items
        """
        def gossip_notify(msg_data_type):
            gossip_notify_message = 501
            print("\nMESSAGE 501: GOSSIP NOTIFY")
            packed_data = struct.pack('!4H', 8, gossip_notify_message, 0, msg_data_type)
            try:
                writer.write(packed_data)
            except:
                print("Something went wrong, please check the connection and restart!")
            subscriptions.add(msg_data_type)


        """
            Function for Gossip to validate
            The message is used to tell Gossip whether the GOSSIP NOTIFICATION with the given
            message ID is well-formed or not. (project specification)
            Packing format: !, network (= big-endian),  standard, 4 items
        """
        def gossip_validation(msg_id, valid):
            gossip_validation_message = 503
            if valid:
                res_and_val = 1
                print("\nMESSAGE 503: GOSSIP VALIDATE!")
            else:
                res_and_val = 0
                print("MESSAGE: GOSSIP INVALIDATE")
            packed_data = struct.pack('!4H', 8, gossip_validation_message, msg_id, res_and_val)
            try:
                writer.write(packed_data)
            except:
                print("Something went wrong, please check the connection and restart!")


        """
            Function for Gossip to make announcements
            Message to instruct Gossip to spread the 
            knowledge about given data item. (project specification)
            Packing format: !, network (= big-endian),  5 items
        """
        def gossip_announce(msg_data, msg_data_type, time_to_live):
            gossip_announce_message = 500
            if time_to_live < 0 or time_to_live >= 16:
                time_to_live = 15
            print("MESSAGE 500: GOSSIP ANNOUNCE")
            res = 0
            num_of_bytes = len(msg_data)
            format_data = '!2H2BH' + str(num_of_bytes) + 's'  
            packed_data = struct.pack(format_data, 8 + len(msg_data), gossip_announce_message, time_to_live, res, msg_data_type, msg_data)
            try:
                writer.write(packed_data)
            except:
                print("Something went wrong, please check the connection and restart!")


        """
            Function for Gossip to make announcements
            This message is sent by Gossip to the module 
            which has previously asked Gossip to notify
            when a message of a particular data type is 
            received by Gossip. (project specification)
            Packing format: !, network (= big-endian),  standard
        """
        def gossip_notification():

            byteorder_big = 'big'
            delayed_gossip_msg = None 
            gossip_notification_message = 502
            pow_match_count = 4
            estimated_peer_count = 0.0
            
            while True:
                yield from asyncio.sleep(0.5)
                print('\nWaiting for notifications from Gossip module......')

                size_in_bytes = yield from reader.read(2)
                nw_size = int.from_bytes(size_in_bytes, byteorder = byteorder_big)
                if nw_size < 4:
                    print("Network Size Estimate Too Small. Number of peers: ", nw_size)
                    yield from reader.read(65535)
                
                with open(nse_hostkey_path, 'r') as file:  
                    hostkey = RSA.importKey(file.read())
                public_key_rsa = hostkey.publickey()
                public_key = public_key_rsa.exportKey(format='PEM')
                public_key = public_key.decode('utf-8')
                pow_value_identifier = datetime.utcnow().replace(minute=0, second=0, microsecond=0)
                hashed = SHA256.new()
                hash_public_key = public_key.encode('utf-8')
                hashed.update(hash_public_key)
                identity = hashed.hexdigest() 
                pow_val = create_pow(identity, pow_match_count)
                c = 0
                rem_data = yield from reader.read(nw_size - 2)
                read_data = size_in_bytes + rem_data
                
                if read_data:
                    msg_compare = int.from_bytes(read_data[2:4], byteorder = byteorder_big)
                    dist_proximity = 1
                    signature = True

                    if msg_compare == gossip_notification_message:
                        print(msg_compare)
                        print(gossip_notification_message)
                        print("\nNot a Gossip notification, clearing buffer!")
                        yield from reader.read(65535)  
                    else:
                        header = struct.unpack('!4H', read_data[:8])
                        nw_size = header[0]
                        msg_id = header[2]
                        msg_data_type = header[1]
                        rem_data = read_data[8:nw_size]
                        print('\nMESSAGE 502: GOSSIP NOTIFICATION')
                        nse_msg_data_type = 521
                        if msg_data_type == nse_msg_data_type:  
                            start_time = str(datetime.utcnow().replace(minute=0, second=0, microsecond=0))
                            start_time = datetime.strptime(start_time, "%Y-%m-%d %H:00:00")
                            nse_msg = ProtocolValidator(start_time, dist_proximity, public_key, pow_val, signature, pow_match_count)
                            
                            if nse_msg is not None:

                                (new_nse_msg, process_delay) = protocol_handler.manage_msg(nse_msg, estimated_peer_count)

                                if new_nse_msg is not None:  

                                    if process_delay != 0:
                                        print("\nValid NSE Message Received!")
                                        gossip_validation(msg_id, True)
                                        
                                        if delayed_gossip_msg is not None:
                                            try:
                                                delayed_gossip_msg.cancel()
                                            except:
                                                print("\nDelayed message from gossip could not be canceled due to some reason!")
                                            finally:
                                                delayed_gossip_msg = None
                                        
                                    else:
                                        print("\nOutdated message, will be invalidated!")
                                        gossip_validation(msg_id, False)
                                    
                                    delayed_gossip_msg = asyncio.ensure_future(gossip_delay(new_nse_msg, process_delay))
                                    estimated_peer_count = pow(2, new_nse_msg.dist_proximity - 0.332747)
                                    nse_estimation_history.append(int(round(estimated_peer_count)))
                                    if len(nse_estimation_history) > nse_history_length:
                                        nse_estimation_history.pop(0) 
                                    print("\nCurrent Network Size Estimate: ", nse_estimation_history)

                                else:
                                    print("\nBest Valid NSE Message Received!")
                                    gossip_validation(msg_id, True)

                            else:
                                print("\nNSE message invalid, invalidate received message!")
                                gossip_validation(msg_id, False)
        

        """
            Delays Gossip Message
        """
        def gossip_delay(msg, process_delay):
            nse_msg_data_type = 666
            if process_delay <= 0:
                process_delay = 0
                print("\nSending Gossip Announce Message Now")
            else:
                print("\nSending Gossip Announce Message In (Sec): ", str(process_delay))
            
            yield from asyncio.sleep(process_delay)
            byte_array = bytearray()
            byte_array.extend(struct.pack("!19s", msg.start_time.encode()))  
            byte_array.extend(struct.pack("!H", msg.dist_proximity))  
            public_key_length = len(msg.public_key)
            public_key_format = "!H" + str(public_key_length) + "s"
            byte_array.extend(struct.pack(public_key_format, public_key_length, msg.public_key.encode()))
            proof_length = len(msg.pow_val)
            proof_format = "!H" + str(proof_length) + "s"
            byte_array.extend(struct.pack(proof_format, proof_length, msg.pow_val.encode()))
            try: 
                byte_array.extend(msg.signature)
            except TypeError as type_error:
                print("Invalid type encountered, running again with new values!")
            convert_message = byte_array
            gossip_announce(convert_message, nse_msg_data_type, 15)


        """
            Makes broadcasts periodically to avoid idle state
            Typically broadcasts every 60 seconds
        """
        def periodic_broadcasts(period):
            nse_msg_data_type = 666
            update_msg = None
            while True:
                update_msg = ProtocolHandler(nse_hostkey_path, pow_match_count)
                msg_update = update_msg.msg
                yield from asyncio.sleep(period)
                print("\nPeriodic Broadcasts Being Made. Can be ignored!")
                byte_array = bytearray()
                byte_array.extend(struct.pack("!19s", msg_update.start_time.encode()))  
                byte_array.extend(struct.pack("!H", msg_update.dist_proximity))  
                public_key_length = len(msg_update.public_key)
                public_key_format = "!H" + str(public_key_length) + "s"
                byte_array.extend(struct.pack(public_key_format, public_key_length, msg_update.public_key.encode()))
                proof_length = len(msg_update.pow_val)
                proof_format = "!H" + str(proof_length) + "s"
                byte_array.extend(struct.pack(proof_format, proof_length, msg_update.pow_val.encode()))
                byte_array.extend(msg_update.signature)
                convert_msg = byte_array
                gossip_announce(convert_msg, nse_msg_data_type, 15)


        print("\nConnecting to gossip module on: " + str(g_api_addr_address) + ":" + str(g_api_addr_port) + '\n')
        try:
            reader, writer = yield from asyncio.streams.open_connection(g_api_addr_address, g_api_addr_port, loop=loop)
        except:
            print("\nConnecting to Gossip failed, please check status, configuration and connection and try again.")
            loop.stop()

        protocol_handler = ProtocolHandler(nse_hostkey_path, pow_match_count)

        yield from asyncio.sleep(2)

        try:
            nse_msg_data_type = 666
            gossip_notify(nse_msg_data_type) 
            closest_msg = protocol_handler.current_closest_msg
            byte_array = bytearray()
            byte_array.extend(struct.pack("!19s", closest_msg.start_time.encode()))  
            byte_array.extend(struct.pack("!H", closest_msg.dist_proximity))  
            public_key_length = len(closest_msg.public_key)
            public_key_format = "!H" + str(public_key_length) + "s"
            byte_array.extend(struct.pack(public_key_format, public_key_length, closest_msg.public_key.encode()))
            proof_length = len(closest_msg.pow_val)
            proof_format = "!H" + str(proof_length) + "s"
            byte_array.extend(struct.pack(proof_format, proof_length, closest_msg.pow_val.encode()))
            byte_array.extend(closest_msg.signature)
            convert_message = byte_array
            gossip_announce(convert_message, nse_msg_data_type, 15) 
            asyncio.ensure_future(periodic_broadcasts(50))
        except:
            print("\nSomething is wrong with the configuration. Please check the settings and run again!")
            sys.exit()

        yield from gossip_notification()
        writer.close()

    loop = asyncio.get_event_loop()
    
    try:
        nse_server = NSEServer()
        nse_server.start(loop)
        asyncio.ensure_future(gossip_handler())
        loop.run_forever()

    except KeyboardInterrupt as keyboard_interrupt:
        print("\nInterrupted by keyboard!")
        pass

    finally:
        nse_server.stop(loop)
        tasks = asyncio.Task.all_tasks(loop)
        for task in tasks:
            task.cancel()
        loop.run_until_complete(asyncio.sleep(0))
        loop.stop()


if __name__ == "__main__":
    print("Gossip Handler Module")