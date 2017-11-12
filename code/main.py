import configparser
import string
import gossip_handler

def parser():

	try:
		# Read the configuration file 
		config = configparser.ConfigParser()
		config.read("config.ini")

		# Store all the values from config file in different variables
		gossip_cache_size = config.get("GOSSIP", "cache_size")
		gossip_max_connections = config.get("GOSSIP", "max_connections")
		gossip_bootstrapper = config.get("GOSSIP", "bootstrapper")
		gossip_listen_address = config.get("GOSSIP", "listen_address")
		gossip_api_address = config.get("GOSSIP", "api_address")
		nse_api_address = config.get("NSE", "api_address")
		nse_history_length = config.get("NSE", "history_length")
		nse_standard_deviation = config.get("NSE", "standard_deviation")
		nse_hostkey_path = config.get("NSE", "hostkey")
		if nse_hostkey_path[0] == '/':
			nse_hostkey_path = nse_hostkey_path[1:]

		# Split address and ports, and store in variables
		g_bootstrapper_address_split = gossip_bootstrapper.split(':')
		g_bootstrapper_address = g_bootstrapper_address_split[0]
		g_bootstrapper_port = g_bootstrapper_address_split[1]
		g_listen_address_split = gossip_listen_address.split(':')
		g_listen_address = g_listen_address_split[0]
		g_listen_port = g_listen_address_split[1]
		g_api_address_split = gossip_api_address.split(':')
		g_api_addr_address = g_api_address_split[0]
		g_api_addr_port = g_api_address_split[1]
		n_api_address_split = nse_api_address.split(':')
		n_api_addr_address = n_api_address_split[0]
		n_api_addr_port = n_api_address_split[1]
		
		print("\nNETWORK SIZE ESTIMATION BY ROYAL BENGAL TIGERS GROUP 41\n")
		print("Configuration File Parsed Successfully")
		print("Address And Ports Split Successfully")
		print("\nPRESS CTRL + C TO HALT THE PROGRAM")

		gossip_handler.define_sockets(nse_hostkey_path, n_api_addr_address, n_api_addr_port, g_api_addr_address, g_api_addr_port, nse_history_length, nse_standard_deviation)

	except FileNotFoundError as file_not_found:
		print("File Not Found")
		print(file_not_found)

	except IOError as io_exception:
		print("IO Exception")
		print(io_exception)

	except configparser.NoSectionError as no_section:
		print("No Section Found")
		print(no_section)

	except configparser.MissingSectionHeaderError as missing_section_header:
		print("Missing Section Header")
		print(missing_section_header)

if __name__ == "__main__":
    parser()