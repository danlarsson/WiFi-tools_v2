A try to create a generic class for WiFi packet captures to be used with a varius set of simple tools.
It uses scapy to capture the packets and the class decodes the packet headers.

This only works on a MAC for now at least

*packet_obj.py* builds a WiFi-packet to be included in the other files.

*packet_test.py* tests and lists information from the *packet_obj.py* object.

*list_retrys_deauth.py* Shows a % of retrys (wrongly) and a Message if it sees a deauth packet. This is a lab with the gole to create a thingie based on RaspberryPi that blinks LEDs depending on what type of packet it sees.
