import unittest
from datetime import datetime
import configparser
import string
from crypto_op import CryptographicOperations
from nse_protocol_handler import ProtocolHandler
from nse_protocol_validator import ProtocolValidator
from tcp_connect import NSEServer
from proof_of_work import *


class TestNSE(unittest.TestCase):

	"""
		Test cases for reading config file
	"""
	def test_gossip_api_address(self):
		config = configparser.ConfigParser()
		config.read("config.ini")
		self.assertEqual(config.get('GOSSIP', 'api_address'), '127.0.0.1:7002')


	def test_gossip_listen_address(self):
		config = configparser.ConfigParser()
		config.read("config.ini")
		self.assertEqual(config.get('GOSSIP', 'listen_address'), '127.0.0.1:6002')


	def test_gossip_bootstrapper_address(self):
		config = configparser.ConfigParser()
		config.read("config.ini")
		self.assertEqual(config.get('GOSSIP', 'bootstrapper'), '127.0.0.1:6002')


	def test_gossip_max_connections(self):
		config = configparser.ConfigParser()
		config.read("config.ini")
		self.assertEqual(config.get('GOSSIP', 'max_connections'), '30')


	def test_gossip_cache_size(self):
		config = configparser.ConfigParser()
		config.read("config.ini")
		self.assertEqual(config.get('GOSSIP', 'cache_size'), '50')


	def test_nse_api_address(self):
		config = configparser.ConfigParser()
		config.read("config.ini")
		self.assertEqual(config.get('NSE', 'api_address'), '127.0.0.1:8002')


	def test_nse_history_length(self):
		config = configparser.ConfigParser()
		config.read("config.ini")
		self.assertEqual(config.get('NSE', 'history_length'), '5')


	def test_nse_standard_devation(self):
		config = configparser.ConfigParser()
		config.read("config.ini")
		self.assertEqual(config.get('NSE', 'standard_deviation'), '15')


	def test_nse_hostkey_path(self):
		config = configparser.ConfigParser()
		config.read("config.ini")
		self.assertEqual(config.get('NSE', 'hostkey'), '/hostkey.pem')


	"""
		Test cases for proof-of-work
	"""
	def test_pow_verify_instance(self):
		pow_problem = str(datetime.utcnow().replace(minute=0, second=0, microsecond=0))
		self.assertIsInstance(verify_pow(pow_problem, 4), bool)


	def test_pow_verify_true(self):
		pow_problem = str(datetime.utcnow().replace(minute=0, second=0, microsecond=0))
		self.assertTrue(verify_pow(pow_problem, 4), True)


	def test_pow_create_instance(self):
		pow_problem = str(datetime.utcnow().replace(minute=0, second=0, microsecond=0))
		self.assertIsInstance(create_pow(pow_problem, 4), str)


	"""
		Test cases for cryptographic operations
	"""
	def test_symmetric_key(self):
		crypt = CryptographicOperations(None, None, None, 2048)
		self.assertEqual(crypt.symmetric_key, None)


	def test_block_size(self):
		crypt = CryptographicOperations(None, None, None, 2048)
		self.assertEqual(crypt.block_size, 32)


	def test_block_size_instance(self):
		crypt = CryptographicOperations(None, None, None, 2048)
		self.assertIsInstance(crypt.block_size, int)


	def test_verify_signature_instance(self):
		crypt = CryptographicOperations(None, None, None, 2048)
		msg = "sample-msg"
		self.assertIsInstance(crypt.sign_msg(msg, None), str)


	def test_verify_signature_instance(self):
		crypt = CryptographicOperations(None, None, None, 2048)
		sig_msg = "sample-sig-msg"
		msg = "sample-msg"
		self.assertIsInstance(crypt.verify_signature(sig_msg, msg), bool)


	"""
		Test cases for protocol handler
	"""
	def test_msg(self):
		ph = ProtocolHandler('hostkey.pem', 4)
		self.assertTrue(ph.msg, ph.form_msg())


	def test_closest_msg(self):
		ph = ProtocolHandler('hostkey.pem', 4)
		self.assertTrue(ph.current_closest_msg, ph.msg)


	def test_future_msg_instance(self):
		ph = ProtocolHandler('hostkey.pem', 4)
		self.assertIsInstance(ph.future_msgs, dict)


	"""
		Test cases for TCP
	"""
	def test_server(self):
		nseserver = NSEServer()
		self.assertEqual(nseserver.server, None)


	def test_client(self):
		nseserver = NSEServer()
		self.assertIsInstance(nseserver.clients, dict)


if __name__ == '__main__':
    unittest.main()