#!/usr/bin/python3

import sys
import socket
import threading

#Hvis len(repr(chr(i) er 3 er det et asci printabe letter. Ellers skal der printes "."))
hex_filter = "".join([(len(repr(chr(i))) == 3) and chr(i) or "." for i in range(256)])

results = list()

def hexdump(data, length=16, show=True):
	if isinstance(data, bytes): #isinstance tjekker om data er i bytes format
		data.decode()

	for i in range(0, len(data), length):
		word = str(data[i:i+length])
		printable = word.translate(hex_filter)
		# endnu en list comprehension der skifter hex repræsentationen af int værdien  
		hexa = ' '.join([f'{ord(c):02x}' for c in word])
		hexwidth = length*3
		results.append(f'{i:04x}   {hexa:<{hexwidth}}   {printable}')

	if show:
		for line in results:
			print (line)
	else:
		return results

def receive_from(connection):
	buffer = b''
	connection.settimeout(10)
	try:
		while True:
			data = connection.recv(4096)
			if not data:
				break
			buffer += data
	except Exception as error:
		print (error)
	return buffer

def proxy_handler (client_socket, remote_host, remote_port, receive_first):
	remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #remote ipv4 tcp socket
	remote_socket.connect((remote_host, remote_port))

	if 

hexdump("Dette er 123 \n en test \ 123 \n")

