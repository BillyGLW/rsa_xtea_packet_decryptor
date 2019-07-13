import struct
import os
import sys
import codecs

import random
import base64

# RSA STUFF
p = 14299623962416399520070177382898895550795403345466153217470516082934737582776038882967213386204600674145392845853859217990626450972452084065728686565928113
q = 7630979195970404721891201847792002125535401292779123937207447574596692788513647179235335529307251350570728407373705564708871762033017096809910315212884101
n = p*q
e = 65537 # coprime e
d = 46730330223584118622160180015036832148732986808519344675210555262940258739805766860224610646919605860206328024326703361630109888417839241959507572247284807035235569619173792292786907845791904955103601652822519121908367187885509270025388641700821735345222087940578381210879116823013776808975766851829020659073
fi = (p-1)*(q-1)



e = '65537' # coprime e 

rsa = "109120132967399429278860960508995541528237502902798129123468757937266291492576446330739696001110603907230888610072655818825358503429057592827629436413108566029093628212635953836686562675849720620786279431090218017681061521755056710823876476444260558147179707119674283982419152118103759076030616683978566631413"
class TibiaLoginPacket(object):
	def __init__(self, packetBytes=bytearray()):
		# XTEA DECRPYTION VAR
		self.DELTA = 0x9E3779B9
		self.MASK = 0xffffffff


		self.packet_size = packetBytes[:2]
		self.adler32_checksum = packetBytes[2:6]
		# [7] skipped byte - 1 (Listed as 0x1 in some places, OTServ discards it) Packet Type
		# [8-9] operatin system 0x2 is windows
		self.os_usage = packetBytes[7:9]
		self.client_version = packetBytes[9:11]
		self.skipped = packetBytes[11:24]
		self.xtea_key = packetBytes[24:40]
		self.username_len = packetBytes[40:42]
		self.encrypted = packetBytes[40:self.handle_packet_size()]
		self.rsa_encrypted = packetBytes[22:self.handle_packet_size()]
		self.position = 0
		# self.username_full = packetBytes[42:self.handle_username_len()]
	def handle_packet_size(self):
		return struct.unpack("H", self.packet_size)[0]
	def handle_adler32_checksum(self):
		return struct.unpack("I", self.adler32_checksum)[0]
	def handle_os(self):
		op = struct.unpack("H", self.os_usage)[0]
			# python 2.7
		if (op==2):
			return "Windows"
		else:
			return "Unix"
	def enumerereversepacket(self):
		m = sum(x*pow(256, i ) for i, x in enumerate(reversed(self.rsa_encrypted)))
		c = pow(m, 65537, int(rsa)) 
		self.rsa_encrypted = bytearray((c >> i ) & 255 for i in reversed(range(0,1024,8)))
		return self.rsa_encrypted
		# return enumerate(reversed(self.rsa_encrypted))
			# python 3.4
		# return "Windows" if op == 2 else print("Unix")
	def handle_adler32_checksum(self):		return struct.unpack("I", self.adler32_checksum)[0]
	def handle_client_version(self):
		return struct.unpack("H", self.client_version)[0]
	def handle_xtea_key(self):
		return struct.unpack("4I", self.xtea_key)[0]
	def handle_xtea_key_decrypt(self):
		return self.xtea_key
	def handle_username_len(self):
		return struct.unpack("H", self.username_len)[0]
	def encrypted_data(self):
		return self.encrypted
	def rsa_encrypted_data(self):
		return self.rsa_encrypted
	def xtea_decrypt(self, key,block,n=32):
	    v0,v1 = struct.unpack("2L",block)
	    k = struct.unpack("4L",key)
	    sum = (self.DELTA * n) & self.MASK
	    for round in range(n):
	        v1 = (v1 - (((v0<<4 ^ v0>>5) + v0) ^ (sum + k[sum>>11 & 3]))) & self.MASK
	        sum = (sum - self.DELTA) & self.MASK
	        v0 = (v0 - (((v1<<4 ^ v1>>5) + v1) ^ (sum + k[sum & 3]))) & self.MASK
	    return struct.pack("2L",v0,v1)


	def rsa_encrypt(self, toencrypt):
		encryptedtodec = ''.join(str(ord(i)) for i in toencrypt)
		msg = pow(int(encryptedtodec), int(e), n)
		return msg

	def rsa_decrypt_new(self, decrypttext):
		msg = pow(decrypttext, d, n)
		return msg



	def otsrc_decrypt(self, ciphertext):
		decrypted_dec = 0
		decrypted_str = ""
		with open('ciphered.txt', 'w') as cmon:
			cmon.write(str(struct.unpack('128b',ciphertext)))
		for i in range(0, 128, 8):
			msg = struct.unpack('d', bytearray(ciphertext[self.position:self.position+7]))
			decrypted_dec = pow(int(msg[0]), d, n)
			decrypted_str += str(decrypted_dec)
			self.position = self.position + 7
		with open("foo.txt", 'w') as foo:
			foo.write(decrypted_str)
		return decrypted_str



	def decrypte(self, pk, ciphertext):
    	#Unpack the key into its components
		key, n = pk
		#Generate the plaintext based on the ciphertext and key using a^b mod m
		plain = [chr((char ** key) % n) for char in ciphertext]
		#Return the array of bytes as a string
		return ''.join(plain)

	def rsa_encrypt_new(self):
		#  m = x
		m = sum(x*pow(256, i) for i, x in enumerate(reversed(self.packet[self.encryptionPos:])))
		c = pow(m, 65537, OT_RSA)
		self.packet[self.encryptionPos:] = bytearray((c >> i) & 255 for i in reversed(range(0, 1024, 8)))
		self.encryptionPos = 0
	def unpack_tibia_packet(self):
		_packed = self.rsa_encrypted
		packet_length = len(_packed)
		print(packet_length)
		packed = ''
		# empty byte, that's where RSA encryption starts
		packed += str(struct.unpack('B', _packed[:1]))
		# xtea key (4 ints)
		packed += str(struct.unpack('4I', _packed[1:17]))
		# username len
		packed += str(struct.unpack('H', _packed[17:19]))
		# username string 
		packed += str(struct.unpack('I', _packed[19:23]))
		# password len 
		packed += str(struct.unpack('H', _packed[23:25]))
		# password string 
		packed += str(struct.unpack('%dH' % ((81-25)/2), _packed[25:81]))
		# hd info
		packed += str(struct.unpack('47B', _packed[81:128]))
		# packed += str(struct.unpack('%iI' % ((111/4)), _packed[17:]))
		return packed
	def what_we_filling(self):
		a = random.randint(0,2)
		if a == 0:
			a = 'B'
			b = 1
		elif a == 1:
			a = 'H'
			b = 2
		elif a == 2:
			a = 'I'
			b = 4
		return a, b

	def bf_unpack_packet(self):
		brute_force_flag = 0
		_packed = self.rsa_encrypted
		packet_length = len(_packed)
		packed = ''
		# empty byte, that's where RSA encryption starts
		packed += str(struct.unpack('B', _packed[:1]))
		# xtea key (4 ints)
		packed += str(struct.unpack('4I', _packed[1:17]))
		# username len
		packed += str(struct.unpack('H', _packed[17:19]))
		loop = 0
		while (brute_force_flag == 0):
			logging = ""
			try:
				for i in range(0, 1):
					loop += 1
					# Randomize if its gonna be 8B,16B or 16B and assign proper character to it.
					fill_byte_method, byte_size = self.what_we_filling()
					# Starting from 19; randomizing the range of brute force (19,100)
					many_times = int((random.randint(19,100)/byte_size))
					# Calculate needed bytes to use struct.unpack 
					needed_bytes =  int(many_times * byte_size) + 19
					# shorthanded unpack method
					method = (str('%d%s' % (many_times, fill_byte_method)))
					packed += str(struct.unpack(method, _packed[19:int(needed_bytes)]))
					# Log out used username bytes
					logging += "Username String: " + method + "+++" + "19:" + str(int(needed_bytes)) + "\n"
					packed += str(struct.unpack('H', _packed[needed_bytes:needed_bytes+2]))
					# Temp variable for next struct.unpack
					password_last_byte = needed_bytes+2
					fill_byte_method, byte_size = self.what_we_filling()
					many_times = int((random.randint(password_last_byte,110)/byte_size))
					
					needed_bytes =  int(many_times * byte_size)
					
					method = (str('%d%s' % (many_times, fill_byte_method)))
					packed += str(struct.unpack(method, _packed[int(password_last_byte):int(many_times + password_last_byte)]))
					last_byte = int(many_times + password_last_byte)
					# print(logging)
					# print(last_byte)
					logging += "Password String: " + method + "+++" + str(password_last_byte) +":" + str(last_byte) + "\n"


					# hd0
					fill_byte_method, byte_size = self.what_we_filling()
					# print(fill_byte_method, byte_size)
					many_times = (128-last_byte)/(byte_size)
					needed_bytes =  int(many_times * byte_size)
					# print(int(many_times))
					method = (str('%d%s' % (many_times, fill_byte_method)))
					logging += "HD String: " + method + "+++" + str(last_byte) + ":128" "\n"
					packed += str(struct.unpack(method, _packed[last_byte:128]))


					print("{}.********OK********".format(loop))
					packed = packed.replace(' ', '')
					packed = packed.replace(',', '')
					packed = packed.replace(',', '')
					packed = packed.replace('(', '')
					packed = packed.replace(')', '')
					# brute_force_flag = 1
					a = self.rsa_decrypt_new(int(packed))
					# print('packed', packed)
					if a[0] == 0:
						print(logging)
						with open('final.txt', 'w') as file:
							file.write(logging)
						brute_force_flag = 1
						i = 10000000001
			except:
				packed = ''
		return packed
	def rsa_encrypt_decrypt(self):
		with open("realrsat.txt", 'r') as file:
			otkey = file.read()

		print(base64.b64encode(rsa.decode("ascii")))
		rsa_private_key = RSA.importKey(otkey)
		rsa_private_key = PKCS1_OAEP.new(rsa_private_key)
		encrypted_text = self.rsa_encrypted_data()
		decrypted_text = rsa_private_key.decrypt(encrypted_text)
		print('your decrypted_text is : {}'.format(decrypted_text))

with open("request.txt", "rb") as file:
	test_packet = file.read()

p_handler = TibiaLoginPacket(test_packet)

decrypted = p_handler.enumerereversepacket()

with open('decrypted.data', 'wb') as _decrypted:
	_decrypted.write(bytearray(decrypted))

print("[+] Packet Size: {0}".format(p_handler.handle_packet_size()))
print("[+] Checksum: {0}".format(p_handler.handle_adler32_checksum()))
print("[+] Operating system: {0}".format(p_handler.handle_os()))
print("[+] Tibia Client: {0}".format(p_handler.handle_client_version()))
print("[+] XTEA: {0}".format(p_handler.handle_xtea_key()))

enc = '15513522885722760521382889933617496562573961821457252216321511571091925712272336\
36713513711813237251591609224425030342331720912619932451022362434819132217297020\
16023914310923319215415860202534418024652181131202252201411281192369256165772532\
40223698849182415713614014034356012832152491902221324158751028105243222107219617\
8'

_tibia_packet = p_handler.bf_unpack_packet()
