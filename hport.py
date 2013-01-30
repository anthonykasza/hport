#!/usr/bin/python

from scapy.all import *
from time import *
from random import *
import syslog

interface="eth0"
syslog.openlog(ident="hport", logoption=syslog.LOG_PID, facility=syslog.LOG_LOCAL0)
half_open = []

def watch_for_it(pkt):
    # Timeout half open connections older than 10 seconds
    for conn in half_open:
      if (conn['time'] < ( time()-10) ):
        del conn
#  Uncomment the following line and adjust indentation in the above lines for IPv6 support
#  if IPv6 in pkt:
    # Port whitelisting
    # be sure the list of ports below corresponds to WL_PORTS in make_firewall.sh
    if TCP in pkt and pkt[TCP].dport in (22,2222,80):
      return
    # SYN pkt handling
    # log SYN pkt info and send SYN+ACK
    elif TCP in pkt and pkt[TCP].flags == 2:
      seqnum = randint(1, 4294967295)
      half_open.append({'time': time(), 'src': pkt[IP].src, 'sport': pkt[IP].sport, 'dport': pkt[TCP].dport, 'seqnum': seqnum})
      p=IP(dst=pkt[IP].src)/TCP(dport=pkt[TCP].sport, sport=pkt[TCP].dport, ack=pkt[TCP].seq+1, seq=seqnum, flags="SA")
      return send(p)
    # ACK pkt handling
    # if ACK corresponds to half open connection, log it, delete it from half open list, and RST connection
    elif TCP in pkt and pkt[TCP].flags in (16, 24, 48):
      for conn in half_open:
        if (conn['src'] == pkt[IP].src) and (conn['sport'] == pkt[TCP].sport) and (conn['dport'] == pkt[TCP].dport) and (conn['time'] > ( time()-10 )) and (conn['seqnum'] == pkt[TCP].ack-1):
          syslog.syslog("{0} a connection from {1}:{2} to port {3}".format(conn['time'], conn['src'], conn['sport'], conn['dport']))
          del conn
          p=IP(dst=pkt[IP].src)/TCP(dport=pkt[TCP].sport, sport=pkt[TCP].dport, ack=pkt[TCP].seq+1, seq=pkt[TCP].ack, flags="R")
          return send(p)
    # All other pkt handling
    else:
      return

sniff(iface=interface, count=0, prn=watch_for_it)
