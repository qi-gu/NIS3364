from kamene.all import send, IP, TCP


send(IP(dst='1.1.1.1')/TCP(sport=11111, dport=80, flags='S', seq=12345))
send(IP(dst='1.1.1.1')/TCP(sport=22222, dport=80, flags='S', seq=12345))