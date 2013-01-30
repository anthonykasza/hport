WL_PORTS="22 80 2222";
INT="eth0";

# IPv4
iptables -F;
for PORT in ${WL_PORTS}
do
        iptables -I INPUT -p tcp --dport ${PORT} -j ACCEPT -i ${INT};
        iptables -I OUTPUT -p tcp --sport ${PORT} -j ACCEPT;
done
iptables -A INPUT -p tcp -m tcp --tcp-flags SYN SYN -j DROP -i ${INT};
iptables -A OUTPUT -p tcp -m tcp --tcp-flags SYN SYN -j DROP;
iptables -A OUTPUT -p tcp -m tcp --tcp-flags RST RST -j DROP;
iptables -A OUTPUT -p icmp --icmp-type 3 -j DROP;

# IPv6
#ip6tables -F;
#for PORT in ${WL_PORTS}
#do
#       ip6tables -I INPUT -p tcp --dport ${PORT} -j ACCEPT -i ${INT};
#       ip6tables -I OUTPUT -p tcp --sport ${PORT} -j ACCEPT;
#done
#ip6tables -A OUTPUT -p icmpv6 --icmpv6-type 1 -j DROP -i ${INT};
#ip6tables -A INPUT -p tcp --tcp-flags SYN SYN -j DROP;
#ip6tables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP;
