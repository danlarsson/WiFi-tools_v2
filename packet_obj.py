# Just a macet object.


from scapy.all import Dot11Elt
import struct

class Mypacket(object):
    def __init__(self, dat):
        self.timestamp = dat.time
        self.fcf = dat.FCfield.value
        self.retry = bool(self.fcf & 8)
        self.tods = bool(self.fcf & 1)
        self.fromds = bool(self.fcf & 2)
        self.wep = bool(self.fcf & 64)
        #
        self.addr1 = dat.addr1
        self.addr2 = dat.addr2
        self.addr3 = dat.addr3
        self.addr4 = dat.addr4
        self.mgmt_frame_subtype = dat.subtype
        self.mgmt_frame_type = dat.type
        self.frequence = dat.Channel # Channel Frequence
        self.datarate = dat.Rate # Datarate the packet was sent with? Skum Data! 
        try:
            self.datarates = dat.rates # Allowed Datarates?
        except:
            self.datarates = None

        self.channel_flags = dat.ChannelFlags.value
        self.signal = dat.dBm_AntSignal
        self.noice  = dat.dBm_AntNoise

        try:
            self.beacon_interval = dat.beacon_interval
        except AttributeError:
            self.beacon_interval = False


        # https://stackoverflow.com/questions/21613091/how-to-use-scapy-to-determine-wireless-encryption-type
        # ls(pcts[9][Dot11Elt]) <- To show different ID-Types in Packets.
        cap = dat.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
                    "{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')  # Don't know what this does??
        
        self.SSID, self.channel, self.crypto = None, None, None
        self.country, self.station_count, self.channel_utilization = None, None, None
        self.bss_transision = None

        try:
            p = dat[Dot11Elt]
            while isinstance(p, Dot11Elt):
                if p.ID == 0: # SSID
                    self.SSID = p.info

                elif p.ID == 3: # Channel
                    self.channel = ord(p.info)

                elif p.ID == 7: # Country
                    try:
                        self.country = p.info[0:2].decode('utf-8')
                    except:
                        self.country = None
                
                elif p.ID == 11:  # QBBS Load Element
                    try:
                        self.station_count, self.channel_utilization, x = struct.unpack('< H b H', p.info)
                        # x = Available Admission Capacity? 
                    except:
                        self.station_count, self.channel_utilization = None, None

                elif p.ID == 48: # Maybe?
                    self.crypto = 'WPA2'

                elif p.ID == 127: # Extended Capabilities
                    o1, o2, o3, o4, o5, o6, o7, o8 = struct.unpack('< b b b b b b b b', p.info)
                    try:
                        self.bss_transision = bool(o3 & 8)  # 802.11r
                    except:
                        self.bss_transision = None

                elif p.ID == 133: # Cisco Devicename
                    try:
                        self.cisco_devicename, self.cisco_clients = struct.unpack('< 10x 16s B 3x', p.info) 
                        self.cisco_devicename = self.cisco_devicename.decode('utf-8')
                    except:
                        self.cisco_devicename = None
                        self.cisco_clients = None

                elif p.ID == 221 and p.info.startswith(b'\x00P\xf2\x01\x01\x00'): # WPA?
                    self.crypto = 'WPA'
                p = p.payload

            if not self.crypto:
                if 'privacy' in cap:
                    self.crypto = 'WEP'
                else:
                    self.crypto = 'OPN'
        except:
            pass

        # ToDo
        # v, k, r, QBSS-Channel-Util, QoS?


    def get_fcf(self, fcf):
        FCfield_flags = {1: 'to-DS', 2: 'from-DS', 4: 'MF', 8: 'retry', 
                 16: 'pw-mgt', 32: 'MD', 64: 'wep', 128: 'order'}
        
        print(FCfield_flags)
        return True

        
    def get_channel_flags(self, channelflags):
        #>>> pcts[1].ChannelFlags.names
        #['res1', 'res2', 'res3', 'res4', 'Turbo', 'CCK', 'OFDM', '2GHz', '5GHz', 'Passive', 'Dynamic_CCK_OFDM', 'GFSK', 'GSM', 'StaticTurbo', '10MHz', '5MHz']
        return True


    def decode_type(self, type, subtype):
        ''' Returns the packet type name in a human readable format
        '''
        try:
            if type == 0:
                dat = ['Associatio Request', 'Association Response', 'Reassociation Request', 'Reassociation Response', 'Probe Request',
                       'Probe Response', '', '', 'Beacon', 'ATIM', 'Disassociation', 'Authentication', 'Deauthentication', 'Action']
                return(dat[subtype])
            elif type == 1:
                dat = ['Block ACK Request', 'Block ACK', 'PS-Poll', 'RTS', 'CTS', 'ACK']
                return(dat[subtype])
            elif type == 2:
                dat = ['Data', '', '', '', 'Null', '', '', '', 'QoS Data', '', '', '', 'Qos Null']
                return(dat[subtype])
        except:
            return('Unknown')

