#!/usr/bin/env python3
import sys
import glob
import zlib

header = b'\tPM9SCREW\t'
knownplaintext = b'\x78\x01' # zlib level 1

def decipher(ciphertext, key, filename = None):
	plaintext = bytearray()
	i = 0
	for c in ciphertext:
		index = (len(ciphertext) - i) % len(key)
		plaintext.append((key[index] ^ ~c) & 0xFF)
		i = i + 1

	try:
		plaintext = zlib.decompress(plaintext)
		if filename != None:
			file = open(filename, 'wb')
			file.write(plaintext)
			file.close()
		return True
	except zlib.error:
		pass

	return False
	
def recover_key_bytes(ciphertexts, knownplaintext, min = 5, max = 32):
	keys = []

	for l in range(min, max + 1):
		possible_match = True
		key = []
		for x in range(0, l):
			key.append(None)

		for ciphertext in ciphertexts:
			for i in range(0, len(knownplaintext)):
				index = (len(ciphertext) - i) % len(key)
				c = (ciphertext[i] ^ ~knownplaintext[i]) & 0xFF
				if key[index] == None:
					key[index] = c
				elif key[index] != c:
					possible_match = False

		if possible_match:
			keys.append(key)

	return keys
	
def brute_force_key(ciphertext, partial_key, idx_missing_bytes):
	if len(idx_missing_bytes) == 0:
		return decipher(ciphertext, partial_key)

	for i in range(0, 256):
		partial_key[idx_missing_bytes[0]] = i
		if brute_force_key(ciphertext, partial_key, idx_missing_bytes[1:]):
			return True

	return False

def print_key(key, prefix = 'Key:'):
	print(f'{prefix} {"".join(f"{c:02x} " for c in key)}')

def main(argv):
	files = []
	ciphertexts = []
	if len(argv) > 0:
		files = argv
	else:
		files = glob.glob('*.php')
		
	if len(files) == 0:
		print('PHP Screw Brute recovers the key for PHP files protected with PHP Screw')
		print(f'Usage: {__file__} <protected PHP files>')
		exit(1)

	for file in files:
		f = open(file, 'rb')
		ciphertexts.append(f.read()[len(header):])
		f.close()

	possible_keys = recover_key_bytes(ciphertexts, knownplaintext)
	for key in possible_keys:
		idx_missing_bytes = []
		for i in range(0, len(key)):
			if key[i] == None:
				key[i] = 0
				idx_missing_bytes.append(i)

		print_key(key, '[+] Trying key:   ')
		if brute_force_key(ciphertexts[0], key, idx_missing_bytes):
			print_key(key, '[!] Recovered key:')
			print('[+] Deciphering files')

			i = 0
			for file in files:
				print(f'[-] {file}')
				decipher(ciphertexts[i], key, file + '.plain')
				i = i + 1
			exit(0)

if __name__ == '__main__':
	main(sys.argv[1:])
