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

hexdump("Dette er 123 \n en test \ 123 \n")

