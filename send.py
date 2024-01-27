from kamene.all import send, IP, ICMP, ARP, TCP, UDP


# ARP测试
send(ARP(psrc="1.1.1.1", pdst="192.168.1.103"))
# IP测试
send(IP(dst="1.1.1.1")/b'Test IP Protocal')
# ICMP测试
send(IP(dst='1.1.1.1')/ICMP(chksum=0x123))
# TCP测试
send(IP(dst='1.1.1.1')/TCP(sport=12345, dport=80, flags='S', seq=12345))
# UDP测试
send(IP(dst='1.1.1.1')/UDP(sport=12345, dport=80))
# IP分片重组测试
send(IP(flags=1,frag=0,id=1,proto=0,dst='1.1.1.1')/b'First Hello Word!!!!!!!!')
send(IP(flags=1,frag=3,id=1,proto=0,dst='1.1.1.1')/(b'second Hello Word!!!!!!!'))
send(IP(flags=0,frag=6,id=2,proto=0,dst='1.1.1.1')/(b'third Hello Word!!'))

send(IP(flags=1,frag=0,id=2,proto=0,dst='1.1.1.1')/b'First Hello Word!!!!!!!!')
send(IP(flags=1,frag=3,id=2,proto=0,dst='1.1.1.1')/(b'second Hello Word!!!!!!!'))
send(IP(flags=0,frag=6,id=1,proto=0,dst='1.1.1.1')/(b'third Hello Word!!'))
