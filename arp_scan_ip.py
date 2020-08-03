#Trasig import

from scapy.all import ARP, Ether

def scan(ip):
    arp_request = ARP(pdst = ip)
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout = 1, verbose = False)[0]

    clients_list = []

    for element in answered_list:
        client_dict = {"ip" : element[1].psrc, "mac" : element[1].hwsrc}
        clients_list.append(client_dict)

    return clients_list 

def Network_Scan(ip):
	arp = scapy.ARP(pdst=ip)
	broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
	ARP_Req_broadcast = arp/broadcast
	answerd = scapy.srp(ARP_Req_broadcast,timeout=1,verbose=False)[0]

	print("\tIP \t\t\t MAC ADDRESS\n------------------------------------------------------")
	for item in answerd:
		print(item[1].psrc + "\t\t" + item[1].hwsrc) 


scan('192.168.1.122')

