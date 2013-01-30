#!/usr/bin/python

from scapy.all import *
from random import *

def watch_for_it(pkt):
    # Port whitelist (SSH)
    if TCP in pkt and pkt[TCP].sport == 2222:
      return
    # SYN pkt
    elif TCP in pkt and pkt[TCP].flags == 2:
      seqnum = randint(1, 4294967295)
      p=IP(dst=pkt[IP].src)/TCP(dport=pkt[TCP].sport, sport=pkt[TCP].dport, ack=pkt[TCP].seq+1, seq=seqnum, flags="SA")
      return send(p)
    # PSHACK
    elif TCP in pkt and pkt[TCP].flags == 24:
      p=IP(dst=pkt[IP].src)/TCP(dport=pkt[TCP].sport, sport=pkt[TCP].dport, ack=pkt[TCP].seq+len(pkt[Raw].load), seq=pkt[TCP].ack, flags="A")
      return send(p)
    # FINACK
    elif TCP in pkt and pkt[TCP].flags == 17:
      p=IP(dst=pkt[IP].src)/TCP(dport=pkt[TCP].sport, sport=pkt[TCP].dport, ack=pkt[TCP].seq+1, seq=pkt[TCP].ack, flags="FA")
      return send(p)
    else:
      return

sniff(iface="eth0", count=0, prn=watch_for_it)

