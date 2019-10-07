# List Packets with the Retry Flag set and Deauth Packets
#
#

# Change the Interface to anything usefull
InterFace = 'en0'

from scapy.all import Dot11, sniff, Dot11Elt, RadioTap, Dot11FCS
from packet_obj import Mypacket

deauth = 0
retry = 0
beacon = 0
all_pkt = 0

def show_pkts(pcts):
    global deauth, retry, beacon, all_pkt
    deauth_hit = False
    retry_hit = False
    if pcts.haslayer(Dot11FCS):  #Dot11Elt / RadioTap
        a = Mypacket(pcts)
        if a.mgmt_frame_type == 0 and a.mgmt_frame_subtype == 12:
            deauth += 1
            deauth_hit = True
        
        elif a.mgmt_frame_type == 0 and a.mgmt_frame_subtype == 8:
            beacon += 1

        if a.retry:
            retry += 1
            retry_hit = True

        all_pkt += 1

        #print('Retry: %f, Deauth: %f, Beacon: %f' % (retry/all_pkt, deauth/all_pkt, beacon/all_pkt))
        if deauth_hit:
            print('[!] Deauth: %i' % deauth, end=', ')
        if retry_hit:
            print('[+] Retry: {0:0.2f}%'.format(retry/all_pkt*100))


# Run
#sniff(iface=InterFace, prn=show_pkts, monitor=True, count=100)
sniff(iface=InterFace, prn=show_pkts, monitor=True)
