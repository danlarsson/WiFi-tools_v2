# Try to create the code to find the WiFi retry packets, when using Scapy.
# wifi.fc.retry = 1 in Wireshark.
# Packet 4 & 7 has the retryflag set. Total 10 packets in the capture.
# 
# We are going to look at the Frame Control Field, which is 2 bytes and include a few interesting bits.

from scapy.all import Dot11, sniff, Dot11Elt, RadioTap, Dot11FCS, rdpcap
#import struct
from packet_obj import Mypacket

InterFace = 'en0'

def show_pkts(pcts):
    if pcts.haslayer(Dot11FCS):  #Dot11Elt / RadioTap
        a = Mypacket(pcts)
        print(a.decode_type(a.mgmt_frame_type, a.mgmt_frame_subtype), end=', ')
        print(a.addr2, end=', ')
        print('%i / %i' % (a.mgmt_frame_type, a.mgmt_frame_subtype), end=', ')
        print(a.retry, end=', ')
        print(a.signal, end=', ')
        print(a.noice, end=', ')
        try:
            print(a.SSID.decode('utf-8'), end=', ')
        except:
            pass
        print(a.channel, end=', ')
        print(a.country, end=', ')
        print(a.crypto, end=', ')
        print(a.datarates, end=', ')
        print(a.channel_utilization, end=', ')
        print('BSS_T:' + str(a.bss_transision))
    else:
        print("Unknown: " + pcts.show())

# Run
sniff(iface=InterFace, prn=show_pkts, monitor=True, count=100)


#pcts = rdpcap('10pkt_dump_with_retrys.pcap')
#pcts = rdpcap('cisco_vendor_name_beacon.pcap')
#pcts = rdpcap('Deauth_attack_100.pcap')

#for packet in pcts:
#    print(packet.FCfield.value)   # 8 = Retry
