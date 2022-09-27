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

def request_handler(buffer):
	#mere kode her
	return buffer

def response_handler(buffer):
	#mere kode her
	return buffer

def proxy_handler (client_socket, remote_host, remote_port, receive_first):
	remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #remote ipv4 tcp socket
	remote_socket.connect((remote_host, remote_port))

	if receive_first:
		remote_buffer = receive_from(remote_socket)
		hexdump(remote_buffer)

	remote_buffer = response_handler(remote_buffer)
	if len(remote_buffer):
		print (f"[+] Sending {len(remote_buffer)} to localhost.")
		client_socket.send(remote_buffer)

	while True:
		local_buffer = receive_from(client_socket)
		if len(local_buffer):
			print(f"[+] Received {len(local_buffer)} bytes from localhost.")
			hexdump(local_buffer)
			
			local_buffer = request_handler(local_buffer) #hvis der skal pilles ved data - ligenu gør den ikke noget
			remote_socket.send(local_buffer) 
			print (f"[+] Sent to target")

		remote_buffer = receive_from(remote_socket)
		if len(remote_buffer):
			print(f"[+] Received {len(remote_buffer)} from remote host.")
			hexdump(remote_buffer)

			remote_buffer = response_handler(remote_buffer) #hvis der skal pilles ved data - ligenu gør den ikke noget
			client_socket.send(remote_buffer)
			print("[+] Sent to localhost.")

		if not len(local_buffer) or not len(remote_buffer):
			client_socket.close()
			remote_socket.close()
			print("[-] No more data. Closing connection.")
			break

def server(local_host, local_port, remote_host, remote_port, receive_first):
	server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		server.bind((local_host, local_port))
	except Exception as error:
		print (error)
		sys.exit(0)

	print (f"[+] Listening on {local_host} : {local_port}")
	server.listen(10)
	while True:
		client_socket, addr = server.accept()
		print(f"[+] Received incomming connection from {addr[0]} {addr[1]}")

		proxy_thread = threading.Thread(target=proxy_handler, args=(client_socket, remote_host, remote_port, receive_first))
		proxy_thread.start()

server("192.168.142.129", 9001, "192.168.142.128", 80, True)

#hexdump("Dette er 123 \n en test \ 123 \n")

