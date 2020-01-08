#
# This program and the accompanying materials are made available under the
# terms of the Eclipse Public License v1.0 which accompanies this distribution,
# and is available at http://www.eclipse.org/legal/epl-v10.html
import socket, sys, os
import argparse
from struct import *
from ctypes import Structure, c_ubyte, c_ushort, c_uint, c_ulonglong

NSH_TYPE1_LEN = 0x6
NSH_MD_TYPE1 = 0x1
NSH_MD_TYPE2 = 0x2
NSH_VERSION1 = int('00', 2)
NSH_NEXT_PROTO_IPV4 = int('00000001', 2)
NSH_NEXT_PROTO_OAM = int('00000100', 2)
NSH_NEXT_PROTO_ETH = int('00000011', 2)
NSH_FLAG_ZERO = int('00000000', 2)

IP_HEADER_LEN = 5
IPV4_HEADER_LEN_BYTES = 20
IPV4_VERSION = 4
IPV4_PACKET_ID = 54321
IPV4_TTL = 255
IPV4_TOS = 0
IPV4_IHL_VER = (IPV4_VERSION << 4) + IP_HEADER_LEN

IPV6_HEADER_LEN_BYTES = 40
IPV6_VERSION = 6
IPV6_CLASS = 0x00
IPV6_FLOW_LABEL = 0x00000
IPV6_PAYLOAD_LEN = 8   #UDP LEN
IPV6_NEXT_HEADER = 0x11
IPV6_HOP_LIMIT = 1
IPV6_VTC_FLOW = ((IPV6_VERSION & 0xF) << 28) | ((IPV6_CLASS & 0xFF) << 20) | (IPV6_FLOW_LABEL &0xFFFFF)

UDP_HEADER_LEN_BYTES = 8

VXLAN_DPORT = 4789
VXLAN_GPE_DPORT = 4790
OLD_VXLAN_GPE_DPORT = 6633

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def int_from_ipv6(addr):
    import struct
    hi, lo = struct.unpack('!QQ', socket.inet_pton(socket.AF_INET6, addr))
    return ((hi << 64) | lo)

class VXLAN(Structure):
    _fields_ = [('flags', c_ubyte),
                ('reserved', c_uint, 16),
                ('next_protocol', c_uint, 8),
                ('vni', c_uint, 24),
                ('reserved2', c_uint, 8)]

    def __init__(self, flags=int('00001000', 2), reserved=0, next_protocol=0,
                 vni=int('111111111111111111111111', 2), reserved2=0, *args, **kwargs):
        super(self.__class__, self).__init__(*args, **kwargs)
        self.flags = flags
        self.reserved = reserved
        self.next_protocol = next_protocol
        self.vni = vni
        self.reserved2 = reserved2

    header_size = 8

    def build(self):
        return pack('!B H B I',
                    self.flags,
                    self.reserved,
                    self.next_protocol,
                    (self.vni << 8) + self.reserved2)

class ETHHEADER(Structure):
    _fields_ = [('dmac0', c_ubyte),
                ('dmac1', c_ubyte),
                ('dmac2', c_ubyte),
                ('dmac3', c_ubyte),
                ('dmac4', c_ubyte),
                ('dmac5', c_ubyte),
                ('smac0', c_ubyte),
                ('smac1', c_ubyte),
                ('smac2', c_ubyte),
                ('smac3', c_ubyte),
                ('smac4', c_ubyte),
                ('smac5', c_ubyte),
                ('ethertype0', c_ubyte),
                ('ethertype1', c_ubyte)]

    header_size = 14

    def build(self):
        return pack('!B B B B B B B B B B B B B B',
                    self.dmac0,
                    self.dmac1,
                    self.dmac2,
                    self.dmac3,
                    self.dmac4,
                    self.dmac5,
                    self.smac0,
                    self.smac1,
                    self.smac2,
                    self.smac3,
                    self.smac4,
                    self.smac5,
                    self.ethertype0,
                    self.ethertype1)

class BASEHEADER(Structure):
    """
    Represent a NSH base header
    """
    _fields_ = [('version', c_ushort, 2),
                ('flags', c_ushort, 8),
                ('length', c_ushort, 6),
                ('md_type', c_ubyte),
                ('next_protocol', c_ubyte),
                ('service_path', c_uint, 24),
                ('service_index', c_uint, 8)]

    def __init__(self, service_path=1, service_index=246, version=NSH_VERSION1, flags=NSH_FLAG_ZERO,
                 length=NSH_TYPE1_LEN, md_type=NSH_MD_TYPE1, proto=NSH_NEXT_PROTO_ETH, *args, **kwargs):
        super(self.__class__, self).__init__(*args, **kwargs)
        self.version = version
        self.flags = flags
        self.length = length
        self.md_type = md_type
        self.next_protocol = proto
        self.service_path = service_path
        self.service_index = service_index

    header_size = 8

    def build(self):
        return pack('!H B B I',
                    (self.version << 14) | (self.flags << 6) | self.length,
                    self.md_type,
                    self.next_protocol,
                    (self.service_path << 8) | self.service_index)


class CONTEXTHEADER(Structure):
    _fields_ = [('network_platform', c_uint),
                ('network_shared', c_uint),
                ('service_platform', c_uint),
                ('service_shared', c_uint)]

    header_size = 16

    def __init__(self, network_platform=0x00, network_shared=0x00, service_platform=0x00, service_shared=0x00, *args,
                 **kwargs):
        super(self.__class__, self).__init__(*args, **kwargs)
        self.network_platform = network_platform
        self.network_shared = network_shared
        self.service_platform = service_platform
        self.service_shared = service_shared

    def build(self):
        return pack('!I I I I',
                    self.network_platform,
                    self.network_shared,
                    self.service_platform,
                    self.service_shared)

class FLOW_METADATA(Structure):
    _fields_ = [('union_label', c_uint),
                ('inner_tag', c_ushort),
                ('src_ip', c_uint),
        ('dst_ip',c_uint),
        ('src_port',c_ushort),
        ('dst_port',c_ushort),
        ('act_dst_vtep',c_uint)]

    header_size = 128 

    def __init__(self, *args, **kwargs):
        super(self.__class__, self).__init__(*args, **kwargs)
        self.union_label = 0x00
        self.inner_tag = 0x00
        self.src_ip = 0x00
        self._pad2 = 0x00
        self._pad4 = 0x00
        self._pad8 = 0x00
        self.dst_ip = 0x00
        self.src_port = 0x00
        self.dst_port = 0x00
        self.act_dst_vtep = 0x00
        self.vni = 0x00
        self.label = 0x00
        self.act_dst_ip = 0x00
        self.act_src_ip = 0x00
        self.act_src_port = 0x00
        self.act_dst_port = 0x00
    
    def build(self):
        packed = b''
        packed += pack('!I H',self.union_label, self.inner_tag)
        packed += pack('!I I Q',self.src_ip, self._pad4, self._pad8)
        packed += pack('!I I Q',self.dst_ip, self._pad4, self._pad8)
        packed += pack('!H H',self.src_port, self.dst_port)
        #packed += pack('!H',_pad2)
        #outer
        packed += pack('!I Q I', self.act_dst_vtep, self._pad8, self.vni)
        #inner
        packed += pack('!H I I Q I I Q', 
                self.label,
                self.act_src_ip,
                self._pad4,
                self._pad8,
                self.act_dst_ip,
                self._pad4,
                self._pad8)

        packed += pack('!H H', self.act_src_port, self.act_dst_port)
        packed += pack('!I I I', self._pad4, self._pad4, self._pad4)
        #packed += pack('!H',_pad2)
    
        packed += pack('!Q Q', self._pad8, self._pad8)


        return packed

class FLOW_ACTION(Structure):
    _fields_ = [('act_dst_vtep', c_uint),
                ('_pad8',c_ulonglong),
        ('act_vxlan_vni',c_uint),
        ('act_ip_family',c_ubyte),
        ('act_ext_action',c_ubyte),
        ('act_inner_tag',c_ushort),
        ('_pad2',c_ushort),
        ('act_src_port',c_ushort),
        ('act_dst_port', c_ushort),
        ('_pad4',c_uint)]

    header_size = 68

    def __init__(self, *args, **kwargs):
        super(self.__class__, self).__init__(*args, **kwargs)
        self.act_dst_vtep = 0x00
        self._pad8 = 0x0
        #self._pad8 = 0x1122334455667788
        self._pad4 = 0x0
        self._pad2 = 0x0
        self.act_vxlan_vni = 0x0
        self.act_inner_tag = 0x00
        self.act_ip_family = 0x0
        self.act_ext_action = 0x00
        self.act_src_port = 0x00
        self.act_dst_port = 0x00
    
    def build(self):
        packed = b''
        packed += pack('!I Q I H B B Q Q Q Q H H I Q',
                                self.act_dst_vtep,
                                self._pad8,
                                self.act_vxlan_vni,
                                self.act_inner_tag,
                                self.act_ip_family,
                                self.act_ext_action,
                                self._pad8,
                                self._pad8,
                                self._pad8,
                                self._pad8,
                                self.act_src_port,
                                self.act_dst_port,
                                self._pad4,
                                self._pad8)
        return packed

class FLOW_KEY(Structure):
    _fields_ = [('union_label', c_uint),
                ('vni', c_uint),
                ('_pad8', c_ulonglong),
        ('src_port',c_ushort),
        ('dst_port',c_ushort)]

    header_size = 44 

    def __init__(self, *args, **kwargs):
        super(self.__class__, self).__init__(*args, **kwargs)
        self.union_label = 0x00
        self.vni = 0x00
        self._pad8 = 0x00
        self.src_port = 0x00
        self.dst_port = 0x00
    
    def build(self):
        packed = b''
        packed += pack('!I I Q Q Q Q H H',
                            self.union_label,
                            self.vni,
                            self._pad8,
                            self._pad8,
                            self._pad8,
                            self._pad8,
                            self.src_port,
                            self.dst_port)
        return packed



class NGP_METADATA(Structure):

    header_size = 2 * FLOW_ACTION.header_size + FLOW_KEY.header_size

    def __init__(self, *args, **kwargs):
        super(self.__class__, self).__init__(*args, **kwargs)
    
        self.action = FLOW_ACTION()
        self.flow_key = FLOW_KEY()

    def build(self):
        packed = b''
        packed += self.action.build()
        packed += self.flow_key.build()
        packed += self.action.build()

        return packed



class NSH_MD2_HEADER(Structure):
    _fields_ = [('md_class', c_ushort),
                ('md2_type', c_ubyte),
                ('length', c_ubyte)]

    header_size = 8 + 4 + NGP_METADATA.header_size

    def __init__(self, md_class=0x00, md2_type=0x00, length=0x00, *args,
                 **kwargs):
        super(self.__class__, self).__init__(*args, **kwargs)
        self.md_class = md_class
        self.md2_type = md2_type
        self.length = (NGP_METADATA.header_size)>>2
        self.ngp_md = NGP_METADATA()

    def build(self):
        packed = b''
        packed += pack('!H B B', self.md_class, self.md2_type, self.length)
    
        packed += self.ngp_md.build()
    
        return packed


class IP4HEADER(Structure):
    _fields_ = [
        ('ip_ihl', c_ubyte),
        ('ip_ver', c_ubyte),
        ('ip_tos', c_ubyte),
        ('ip_tot_len', c_ushort),
        ('ip_id', c_ushort),
        ('ip_frag_offset', c_ushort),
        ('ip_ttl', c_ubyte),
        ('ip_proto', c_ubyte),
        ('ip_chksum', c_ushort),
        ('ip_saddr', c_uint),
        ('ip_daddr', c_uint)]

    header_size = 20

    def build(self):
        ip_header_pack = pack('!B B H H H B B H I I', IPV4_IHL_VER, self.ip_tos, self.ip_tot_len, self.ip_id,
                              self.ip_frag_offset, self.ip_ttl, self.ip_proto, self.ip_chksum, self.ip_saddr,
                              self.ip_daddr)
        return ip_header_pack

    def set_ip_checksum(self, checksum):
        self.ip_chksum = checksum

class IP6HEADER(Structure):
    _fields_ = [
        ('ip6_ver', c_ubyte),
        ('ip6_cls', c_ubyte),
        ('ip6_flow', c_ubyte),
        ('ip6_pl_len', c_ushort),
        ('ip6_nxt_hd', c_ubyte),
        ('ip6_hop_lmt', c_ubyte),
        ('ip6_saddr_0', c_ulonglong),
        ('ip6_saddr_1', c_ulonglong),
        ('ip6_daddr_0', c_ulonglong),
        ('ip6_daddr_1', c_ulonglong)]

    header_size = 20
    
    def __init__(self, ip6_pl_len=0x0000, ip6_nxt_hd=0x11, ip6_hop_lmt=0x01, ipv6_src=None, ipv6_dst=None):
        self.ip6_pl_len = ip6_pl_len
        self.ip6_nxt_hd = ip6_nxt_hd
        self.ip6_hop_lmt = ip6_hop_lmt
        self.ip6_saddr_0 = 0x0000000000000000
        self.ip6_saddr_1 = 0x0000000000000000
        self.ip6_daddr_0 = 0x0000000000000000
        self.ip6_daddr_1 = 0x0000000000000000
        if ipv6_src:
           ipv6_saddr = int_from_ipv6(ipv6_src)
           self.ip6_saddr_0 = (ipv6_saddr >> 64) & 0xFFFFFFFFFFFFFFFF
           self.ip6_saddr_1 = (ipv6_saddr >> 0) & 0xFFFFFFFFFFFFFFFF
        if ipv6_dst:
           ipv6_daddr = int_from_ipv6(ipv6_dst)
           self.ip6_daddr_0 = (ipv6_daddr >> 64) & 0xFFFFFFFFFFFFFFFF
           self.ip6_daddr_1 = (ipv6_daddr >> 0) & 0xFFFFFFFFFFFFFFFF

    def build(self):
        ip6_header_pack = pack('!I H B B Q Q Q Q', IPV6_VTC_FLOW, self.ip6_pl_len, self.ip6_nxt_hd, self.ip6_hop_lmt,
                               self.ip6_saddr_0, self.ip6_saddr_1, self.ip6_daddr_0, self.ip6_daddr_1)
        return ip6_header_pack

class UDPHEADER(Structure):
    """
    Represents a UDP header
    """
    _fields_ = [
        ('udp_sport', c_ushort),
        ('udp_dport', c_ushort),
        ('udp_len', c_ushort),
        ('udp_sum', c_ushort)]

    header_size = 8

    def build(self):
        udp_header_pack = pack('!H H H H', self.udp_sport, self.udp_dport, self.udp_len,
                               self.udp_sum)
        return udp_header_pack

class PSEUDO_UDPHEADER(Structure):
    """ Pseudoheader used in the UDP checksum."""

    def __init__(self):
        self.src_ip = 0
        self.dest_ip = 0
        self.zeroes = 0
        self.protocol = 17
        self.length = 0

    def build(self):
        """ Create a string from a pseudoheader """
        p_udp_header_pack = pack('!I I B B H', self.src_ip, self.dest_ip,
                                 self.zeroes, self.protocol, self.length)
        return p_udp_header_pack

class PSEUDO_IPV6_UDPHEADER(Structure):
    """ Pseudoheader used in the ipv6 UDP checksum."""

    def __init__(self):
        self.src_ip6_0 = 0
        self.src_ip6_1 = 0
        self.dest_ip6_0 = 0
        self.dest_ip6_1 = 0
        self.zeroes = 0
        self.protocol = 17
        self.length = 0

    def build(self):
        """ Create a string from a pseudoheader """
        p_ipv6_udp_header_pack = pack('!QQ QQ B B H', self.src_ip6_0, self.src_ip6_1,
                                 self.dest_ip6_0, self.dest_ip6_1,
                                 self.zeroes, self.protocol, self.length)
        return p_ipv6_udp_header_pack

class TCPHEADER(Structure):
    """
    Represents a TCP header
    """
    _fields_ = [
        ('tcp_sport', c_ushort),
        ('tcp_dport', c_ushort),
        ('tcp_len', c_ushort),
        ('tcp_sum', c_ushort)]

    header_size = 8


def decode_eth(payload, offset, eth_header_values):
    eth_header = payload[offset:(offset+14)]

    _header_values = unpack('!B B B B B B B B B B B B B B', eth_header)
    eth_header_values.dmac0 = _header_values[0]
    eth_header_values.dmac1 = _header_values[1]
    eth_header_values.dmac2 = _header_values[2]
    eth_header_values.dmac3 = _header_values[3]
    eth_header_values.dmac4 = _header_values[4]
    eth_header_values.dmac5 = _header_values[5]
    eth_header_values.smac0 = _header_values[6]
    eth_header_values.smac1 = _header_values[7]
    eth_header_values.smac2 = _header_values[8]
    eth_header_values.smac3 = _header_values[9]
    eth_header_values.smac4 = _header_values[10]
    eth_header_values.smac5 = _header_values[11]
    eth_header_values.ethertype0 = _header_values[12]
    eth_header_values.ethertype1 = _header_values[13]

def decode_ip(payload, ip_header_values):
    ip_header = payload[14:34]

    _header_values = unpack('!B B H H H B B H I I', ip_header)
    ip_header_values.ip_ihl = _header_values[0] & 0x0F
    ip_header_values.ip_ver = _header_values[0] >> 4
    ip_header_values.ip_tos = _header_values[1]
    ip_header_values.ip_tot_len = _header_values[2]
    ip_header_values.ip_id = _header_values[3]
    ip_header_values.ip_frag_offset = _header_values[4]
    ip_header_values.ip_ttl = _header_values[5]
    ip_header_values.ip_proto = _header_values[6]
    ip_header_values.ip_chksum = _header_values[7]
    ip_header_values.ip_saddr = _header_values[8]
    ip_header_values.ip_daddr = _header_values[9]

def decode_udp(payload, udp_header_values):
    udp_header = payload[34:42]

    _header_values = unpack('!H H H H', udp_header)
    udp_header_values.udp_sport = _header_values[0]
    udp_header_values.udp_dport = _header_values[1]
    udp_header_values.udp_len = _header_values[2]
    udp_header_values.udp_sum = _header_values[3]

def decode_tcp(payload, offset, tcp_header_values):
    tcp_header = payload[offset:(offset+8)]

    _header_values = unpack('!H H H H', tcp_header)
    tcp_header_values.tcp_sport = _header_values[0]
    tcp_header_values.tcp_dport = _header_values[1]
    tcp_header_values.tcp_len = _header_values[2]
    tcp_header_values.tcp_sum = _header_values[3]

def decode_vxlan(payload, vxlan_header_values):
    """Decode the VXLAN header for a received packets"""
    vxlan_header = payload[42:50]

    _header_values = unpack('!B H B I', vxlan_header)
    vxlan_header_values.flags = _header_values[0]
    vxlan_header_values.reserved = _header_values[1]
    vxlan_header_values.next_protocol = _header_values[2]

    vni_rsvd2 = _header_values[3]
    vxlan_header_values.vni = vni_rsvd2 >> 8
    vxlan_header_values.reserved2 = vni_rsvd2 & 0x000000FF

def decode_nsh_baseheader(payload, offset, nsh_base_header_values):
    """Decode the NSH base headers for a received packets"""
    base_header = payload[offset:(offset+8)]

    _header_values = unpack('!H B B I', base_header)
    start_idx = _header_values[0]
    nsh_base_header_values.md_type = _header_values[1]
    nsh_base_header_values.next_protocol = _header_values[2]
    path_idx = _header_values[3]

    nsh_base_header_values.version = start_idx >> 14
    nsh_base_header_values.flags = start_idx >> 6
    nsh_base_header_values.length = start_idx >> 0
    nsh_base_header_values.service_path = path_idx >> 8
    nsh_base_header_values.service_index = path_idx & 0x000000FF

def decode_nsh_contextheader(payload, offset, nsh_context_header_values):
    """Decode the NSH context headers for a received packet"""
    context_header = payload[offset:(offset+16)]

    _header_values = unpack('!I I I I', context_header)
    nsh_context_header_values.network_platform = _header_values[0]
    nsh_context_header_values.network_shared = _header_values[1]
    nsh_context_header_values.service_platform = _header_values[2]
    nsh_context_header_values.service_shared = _header_values[3]

def compute_internet_checksum(data):
    """
    Function for Internet checksum calculation. Works
    for both IP and UDP.
    """
    checksum = 0
    n = len(data) % 2
    # data padding
    pad = bytearray('', encoding='UTF-8')
    if n == 1:
        pad = bytearray(b'\x00')
    # for i in range(0, len(data + pad) - n, 2):
    for i in range(0, len(data)-1, 2):
        checksum += (ord(data[i]) << 8) + (ord(data[i + 1]))
    if n == 1:
        checksum += (ord(data[len(data)-1]) << 8) + (pad[0])
    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    checksum = ~checksum & 0xffff
    return checksum

# Implements int.from_bytes(s, byteorder='big')
def int_from_bytes(s):
    return sum(ord(c) << (i * 8) for i, c in enumerate(s[::-1]))

def build_ethernet_header_swap(myethheader):
    """ Build Ethernet header """
    newethheader=ETHHEADER()
    newethheader.smac0 = myethheader.dmac0
    newethheader.smac1 = myethheader.dmac1
    newethheader.smac2 = myethheader.dmac2
    newethheader.smac3 = myethheader.dmac3
    newethheader.smac4 = myethheader.dmac4
    newethheader.smac5 = myethheader.dmac5

    newethheader.dmac0 = myethheader.smac0
    newethheader.dmac1 = myethheader.smac1
    newethheader.dmac2 = myethheader.smac2
    newethheader.dmac3 = myethheader.smac3
    newethheader.dmac4 = myethheader.smac4
    newethheader.dmac5 = myethheader.smac5

    newethheader.ethertype0 = myethheader.ethertype0
    newethheader.ethertype1 = myethheader.ethertype1
    return newethheader

def build_ipv4_header(ip_tot_len, proto, src_ip, dest_ip, swap_ip):
    """
    Builds a complete IP header including checksum
    """

    if src_ip:
        ip_saddr = socket.inet_aton(src_ip)
    else:
        ip_saddr = socket.inet_aton(socket.gethostbyname(socket.gethostname()))

    if (swap_ip == True):
        new_ip_daddr = int_from_bytes(ip_saddr)
        new_ip_saddr = socket.inet_aton(dest_ip)
        new_ip_saddr = int_from_bytes(new_ip_saddr)
    else:
        new_ip_saddr = int_from_bytes(ip_saddr)
        new_ip_daddr = int_from_bytes(socket.inet_aton(dest_ip))

    ip_header = IP4HEADER(IP_HEADER_LEN, IPV4_VERSION, IPV4_TOS, ip_tot_len, IPV4_PACKET_ID, 0, IPV4_TTL, proto, 0, new_ip_saddr, new_ip_daddr)

    checksum = compute_internet_checksum(ip_header.build())
    ip_header.set_ip_checksum(checksum)
    ip_header_pack = ip_header.build()

    return ip_header, ip_header_pack

def build_ipv6_header(play_load_len, proto, hop_limit, ipv6_src, ipv6_dst, swap_ip=False):
    
    if swap_ip:
        new_ipv6_src = ipv6_dst
        new_ipv6_dst = ipv6_src
    else:
        new_ipv6_src = ipv6_src
        new_ipv6_dst = ipv6_dst

    ipv6_header = IP6HEADER(play_load_len, proto, hop_limit, new_ipv6_src, new_ipv6_dst)
    ipv6_header_pack = ipv6_header.build()

    return ipv6_header, ipv6_header_pack

def build_ipv6_udp_header(src_port, dest_port, ipv6_header, data):

    # build UDP header with sum = 0
    udp_header = UDPHEADER(src_port, dest_port, UDP_HEADER_LEN_BYTES + len(data), 0)
    udp_header_pack = udp_header.build()

    # build Pseudo Header
    p_header = PSEUDO_IPV6_UDPHEADER()
    p_header.dest_ip6_0 = ((ipv6_header.ip6_daddr_0 < 64) & 0xFFFFFFFFFFFFFFFF)
    p_header.dest_ip6_1 = (ipv6_header.ip6_daddr_1 & 0xFFFFFFFFFFFFFFFF)
    p_header.src_ip6_0 = ((ipv6_header.ip6_saddr_0 < 64) & 0xFFFFFFFFFFFFFFFF)
    p_header.src_ip6_1 = (ipv6_header.ip6_saddr_1 & 0xFFFFFFFFFFFFFFFF)
    p_header.length = udp_header.udp_len

    p_header_pack = p_header.build()

    udp_checksum = compute_internet_checksum(p_header_pack + udp_header_pack + data)
    udp_header.udp_sum = udp_checksum
    # pack UDP header again but this time with checksum
    udp_header_pack = udp_header.build()

    return udp_header, udp_header_pack

def build_udp_header(src_port, dest_port, ip_header, data):
    """
    Building an UDP header requires fields from
    IP header in order to perform checksum calculation
    """

    # build UDP header with sum = 0
    udp_header = UDPHEADER(src_port, dest_port, UDP_HEADER_LEN_BYTES + len(data), 0)
    udp_header_pack = udp_header.build()

    # build Pseudo Header
    p_header = PSEUDO_UDPHEADER()
    p_header.dest_ip = ip_header.ip_daddr
    p_header.src_ip = ip_header.ip_saddr
    p_header.length = udp_header.udp_len

    p_header_pack = p_header.build()

    udp_checksum = compute_internet_checksum(p_header_pack + udp_header_pack + data)
    udp_header.udp_sum = udp_checksum
    # pack UDP header again but this time with checksum
    udp_header_pack = udp_header.build()

    return udp_header, udp_header_pack

def build_udp_packet(src_ip, dest_ip, src_port, dest_port, data, swap_ip):
    """
    Data needs to encoded as Python bytes. In the case of strings
    this means a bytearray of an UTF-8 encoding
    """

    total_len = len(data) + IPV4_HEADER_LEN_BYTES + UDP_HEADER_LEN_BYTES
    # First we build the IP header
    ip_header, ip_header_pack = build_ipv4_header(total_len, socket.IPPROTO_UDP, src_ip, dest_ip, swap_ip)

    # Build UDP header
    udp_header, udp_header_pack = build_udp_header(src_port, dest_port, ip_header, data)

    udp_packet = ip_header_pack + udp_header_pack + data

    return udp_packet

def build_ipv6_udp_packet(src_ip, dest_ip, src_port, dest_port, data, swap_ip):

    total_len = len(data) + IPV6_HEADER_LEN_BYTES + UDP_HEADER_LEN_BYTES
    # First we build the IP header
    ipv6_header, ipv6_header_pack = build_ipv6_header(total_len, socket.IPPROTO_UDP, 0x01, src_ip, dest_ip, swap_ip)

    # Build UDP header
    udp_header, udp_header_pack = build_ipv6_udp_header(src_port, dest_port, ipv6_header, data)

    udp_packet = ipv6_header_pack + udp_header_pack + data

    return udp_packet

def getmac(interface):
  try:
    mac = open('/sys/class/net/'+interface+'/address').readline()
  except:
    mac = None
  return mac

def getmacbyip(ip):
    os.popen('ping -c 1 %s' % ip)
    fields = os.popen('grep "%s " /proc/net/arp' % ip).read().split()
    if len(fields) == 6 and fields[3] != "00:00:00:00:00:00":
        mac = fields[3]
    else:
        mac = None
    return mac

def print_ethheader(ethheader):
    print("Eth Dst MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x, Src MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x, Ethertype: 0x%.4x" % (ethheader.dmac0, ethheader.dmac1, ethheader.dmac2, ethheader.dmac3, ethheader.dmac4, ethheader.dmac5, ethheader.smac0, ethheader.smac1, ethheader.smac2, ethheader.smac3, ethheader.smac4, ethheader.smac5, (ethheader.ethertype0<<8) | ethheader.ethertype1))

def print_ipheader(ipheader):
    print("IP Version: %s IP Header Length: %s, TTL: %s, Protocol: %s, Src IP: %s, Dst IP: %s" % (ipheader.ip_ver, ipheader.ip_ihl, ipheader.ip_ttl, ipheader.ip_proto, str(socket.inet_ntoa(pack('!I', ipheader.ip_saddr))), str(socket.inet_ntoa(pack('!I', ipheader.ip_daddr)))))

def print_udpheader(udpheader):
    print ("UDP Src Port: %s, Dst Port: %s, Length: %s, Checksum: %s" % (udpheader.udp_sport, udpheader.udp_dport, udpheader.udp_len, udpheader.udp_sum))

def print_vxlanheader(vxlanheader):
    print("VxLAN/VxLAN-gpe VNI: %s, flags: %.2x, Next: %s" % (vxlanheader.vni, vxlanheader.flags, vxlanheader.next_protocol))

def print_nsh_baseheader(nshbaseheader):
    print("NSH base nsp: %s, nsi: %s, md_type:%s" % (nshbaseheader.service_path, nshbaseheader.service_index, nshbaseheader.md_type))

def print_nsh_md2(md2):
    print ("nsh md2 length:%d nsh md2 act dst vtep ip:%s" % (NSH_MD2_HEADER.header_size, md2.ngp_md.action.act_dst_vtep)) 


def print_nsh_contextheader(nshcontextheader):
    print("NSH context c1: 0x%.8x, c2: 0x%.8x, c3: 0x%.8x, c4: 0x%.8x" % (nshcontextheader.network_platform, nshcontextheader.network_shared, nshcontextheader.service_platform, nshcontextheader.service_shared))

def main():
    parser = argparse.ArgumentParser(description='This is a VxLAN/VxLAN-gpe + NSH dump and forward tool, you can use it to dump and forward VxLAN/VxLAN-gpe + NSH packets, it can also act as an NSH-aware SF for SFC test when you use --forward option, in that case, it will automatically decrease nsi by one.', prog='vxlan_tool.py')
    parser.add_argument('-i', '--interface',
                        help='Specify the interface to listen')
    parser.add_argument('-o', '--output',
                        help='Specify the interface to send on')
    parser.add_argument('-iipv', '--inner_ip_version', choices=['4','6'], default='4',
                        help='Specify inner pkt ip version')
    parser.add_argument('-oipv', '--outer_ip_version', choices=['4','6'], default='4',
                        help='Specify out pkt ip version')
    parser.add_argument('-d', '--do', choices=['dump', 'forward', 'nsh_proxy', 'send'],
                        help='dump/foward/send VxLAN/VxLAN-gpe + NSH or Eth + NSH packet')
    parser.add_argument('-t', '--type', choices=['eth_nsh', 'vxlan_gpe_nsh', 'vxlan'], default='vxlan_gpe_nsh',
                        help='Specify packet type for send: eth_nsh or vxlan_gpe_nsh')
    parser.add_argument('--outer-source-mac',
                        help='Specify outer source MAC for packet send')
    parser.add_argument('--outer-destination-mac',
                        help='Specify outer destination MAC for packet send')
    parser.add_argument('--outer-source-ip',
                        help='Specify outer source IP address for packet send')
    parser.add_argument('--outer-destination-ip',
                        help='Specify outer destination IP address for packet send')
    parser.add_argument('--outer-source-udp-port', type=int,
                        help='Specify outer source UDP port for packet send')
    parser.add_argument('--inner-source-mac',
                        help='Specify inner source MAC for packet send')
    parser.add_argument('--inner-destination-mac',
                        help='Specify inner destination MAC for packet send')
    parser.add_argument('--inner-source-ip',
                        help='Specify inner source IP address for packet send')
    parser.add_argument('--inner-destination-ip',
                        help='Specify inner destination IP address for packet send')
    parser.add_argument('--inner-source-udp-port', type=int,
                        help='Specify inner source UDP port for packet send')
    parser.add_argument('--inner-destination-udp-port', type=int,
                        help='Specify inner destination UDP port for packet send')
    parser.add_argument('-n', '--number', type=int,
                        help='Specify number of packet to send')
    parser.add_argument('--no-swap-ip', dest='swap_ip', default=True, action='store_false',
                        help="won't swap ip if provided")
    parser.add_argument('-v', '--verbose', choices=['on', 'off'],
                        help='dump packets when in forward mode')
    parser.add_argument('--forward-inner', '-f', dest='forward_inner',
                        default=False, action='store_true',
                        help='Strip the outer encapsulation and forward the inner packet')
    parser.add_argument('--block', '-b', type=int, default=0,
                        help='Acts as a firewall dropping packets that match this TCP dst port')
    parser.add_argument('--source-block', type=int, default=0,
                        help='Acts as a firewall dropping packets that match this TCP src port')

    args = parser.parse_args()
    macaddr = None
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        if args.interface is not None:
            s.bind((args.interface, 0))
        output = args.output if args.output else args.interface
        if ((args.do == "forward") or (args.do == "nsh_proxy") or (args.do == "send")):
            if output is None:
                print("Error: you must specify the interface for forward and send")
                sys.exit(-1)
            send_s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            send_s.bind((output, 0))
        if args.interface is not None:
            macstring = getmac(args.interface)
            if (macstring is not None):
                macaddr = macstring.strip().split(':')
        if output is not None:
            output_macstring = getmac(output)
        if (args.do == "send"):
            if (args.inner_source_mac is None):
                args.inner_source_mac = output_macstring
            if (args.inner_destination_mac is None):
                print("Error: you must specify inner destination MAC for packet send")
                sys.exit(-1)
            if (args.inner_source_ip is None) or (args.inner_destination_ip is None):
                print("Error: you must specify inner source IP and inner destination IP for packet send")
                sys.exit(-1)
            if (args.outer_source_mac is None):
                args.outer_source_mac = args.inner_source_mac
            if (args.outer_destination_mac is None):
                args.outer_destination_mac = args.inner_destination_mac
            if (args.outer_source_ip is None):
                args.outer_source_ip = args.inner_source_ip
            if (args.outer_destination_ip is None):
                args.outer_destination_ip = args.inner_destination_ip
            if (args.outer_source_udp_port is None):
                args.outer_source_udp_port = 55651
            if (args.inner_source_udp_port is None):
                args.inner_source_udp_port = args.outer_source_udp_port
            if (args.inner_destination_udp_port is None):
                args.inner_destination_udp_port = 25
            if (args.number is None):
                args.number = 10

    except OSError as e:
        print("{}".format(e) + " '%s'" % args.interface)
        sys.exit(-1)

    do_print = ((args.do != "forward") or (args.verbose == "on"))

    vxlan_gpe_udp_ports = [VXLAN_GPE_DPORT, OLD_VXLAN_GPE_DPORT]
    vxlan_udp_ports = [VXLAN_DPORT] + vxlan_gpe_udp_ports

    #header len
    eth_length = 14
    ip_length = 20
    udp_length = 8
    vxlan_length = 8
    nshbase_length = 8
    nshcontext_length = 16

    """ For NSH proxy """
    vni = 0;
    # NSP+NSI to VNI Mapper
    nsh_to_vni_mapper = {}
    # VNI to NSH Mapper
    vni_to_nsh_mapper = {}

    """ Send VxLAN/VxLAN-gpe + NSH packet """
    if (args.do == "send"):
        myethheader = ETHHEADER()
        myipheader = IP4HEADER()
        myudpheader = UDPHEADER()
        myvxlanheader = VXLAN()
        mynshbaseheader = BASEHEADER()
        mynshcontextheader = CONTEXTHEADER()
        md2 = NSH_MD2_HEADER()

        """ Set Ethernet header """
        dstmacaddr = args.outer_destination_mac.split(":")
        myethheader.dmac0 = int(dstmacaddr[0], 16)
        myethheader.dmac1 = int(dstmacaddr[1], 16)
        myethheader.dmac2 = int(dstmacaddr[2], 16)
        myethheader.dmac3 = int(dstmacaddr[3], 16)
        myethheader.dmac4 = int(dstmacaddr[4], 16)
        myethheader.dmac5 = int(dstmacaddr[5], 16)

        myethheader.smac0 = int(macaddr[0], 16)
        myethheader.smac1 = int(macaddr[1], 16)
        myethheader.smac2 = int(macaddr[2], 16)
        myethheader.smac3 = int(macaddr[3], 16)
        myethheader.smac4 = int(macaddr[4], 16)
        myethheader.smac5 = int(macaddr[5], 16)

        if (args.outer_ip_version == "6"):
            myethheader.ethertype0 = 0x86
            myethheader.ethertype1 = 0xDD
        else:    
            myethheader.ethertype0 = 0x08
            myethheader.ethertype1 = 0x00

        """ Set VxLAN header """
        myvxlanheader.flags = int('00001100',2)
        myvxlanheader.reserved = 0
        myvxlanheader.next_protocol = 0x04
        myvxlanheader.vni = 0x7D2
        myvxlanheader.reserved2 = 0

        """ Set NSH base header """
        #mynshbaseheader.flags = NSH_FLAG_ZERO
        mynshbaseheader.flags = int('00000110',2)
        #mynshbaseheader.length = NSH_TYPE1_LEN
        #mynshbaseheader.md_type = NSH_MD_TYPE1
        mynshbaseheader.length =  (NSH_MD2_HEADER.header_size)>>2 #warning: 6 bits
        print ("nsh md2 length:%d " % mynshbaseheader.length)

        mynshbaseheader.md_type = NSH_MD_TYPE2
        mynshbaseheader.next_protocol = NSH_NEXT_PROTO_ETH
        mynshbaseheader.service_path = 1 
        mynshbaseheader.service_index = 248

        """ Set NSH md2 header """
        md2.ngp_md.action.act_dst_vtep = int_from_bytes(socket.inet_aton(args.outer_source_ip))
        md2.ngp_md.action.act_dst_port = args.inner_source_udp_port
        md2.ngp_md.action.act_src_port = args.inner_destination_udp_port + 1

        
        """ Set NSH context header """
        mynshcontextheader.network_platform = int_from_bytes(socket.inet_aton(args.outer_destination_ip))
        mynshcontextheader.network_shared = 0x1234
        mynshcontextheader.service_platform = 0xc0a83c28
        mynshcontextheader.service_shared = 0x87654321

        if (args.inner_ip_version == "6"):
            innerippack = build_ipv6_udp_packet(args.inner_source_ip, args.inner_destination_ip, args.inner_source_udp_port, args.inner_destination_udp_port, "Hellow, World!!!".encode('utf-8'), False)
        else: 
            innerippack = build_udp_packet(args.inner_source_ip, args.inner_destination_ip, args.inner_source_udp_port, args.inner_destination_udp_port, "Hellow, World!!!".encode('utf-8'), False)

        if (args.type == "vxlan_gpe_nsh"):
            if (mynshbaseheader.md_type == NSH_MD_TYPE2):
                outerippack = build_udp_packet(args.outer_source_ip, args.outer_destination_ip, args.outer_source_udp_port, VXLAN_GPE_DPORT, myvxlanheader.build() + mynshbaseheader.build() + md2.build() + myethheader.build() + innerippack, False)
            else :
                outerippack = build_udp_packet(args.outer_source_ip, args.outer_destination_ip, args.outer_source_udp_port, VXLAN_GPE_DPORT, myvxlanheader.build() + mynshbaseheader.build() + mynshcontextheader.build() + myethheader.build() + innerippack, False)
        elif (args.type == "eth_nsh"):
            outerippack = mynshbaseheader.build() + mynshcontextheader.build() + myethheader.build() + innerippack
            myethheader.ethertype0 = 0x89
            myethheader.ethertype1 = 0x4f
        elif (args.type == "vxlan"):
            myvxlanheader.next_protocol = 0x03
            if (args.inner_ip_version == "6"):            
                myethheader.ethertype0 = 0x86
                myethheader.ethertype1 = 0xDD
            else:
                myethheader.ethertype0 = 0x08
                myethheader.ethertype1 = 0x00
            outerippack = build_udp_packet(args.outer_source_ip, args.outer_destination_ip, args.outer_source_udp_port, VXLAN_DPORT, myvxlanheader.build() + myethheader.build()+ innerippack, False)


        """ Build Ethernet packet """
        if (args.outer_ip_version == "6"):            
            myethheader.ethertype0 = 0x86
            myethheader.ethertype1 = 0xDD
        else:
            myethheader.ethertype0 = 0x08
            myethheader.ethertype1 = 0x00
        ethpkt = myethheader.build() + outerippack

        """ Decode ethernet header """
        decode_eth(ethpkt, 0, myethheader)

        if (args.type == "eth_nsh"):
            offset = eth_length
            decode_nsh_baseheader(ethpkt, offset, mynshbaseheader)
            decode_nsh_contextheader(ethpkt, offset + nshbase_length, mynshcontextheader)
        elif (args.type == "vxlan_gpe_nsh"):
            """ Decode IP header """
            decode_ip(ethpkt, myipheader)

            """ Decode UDP header """
            decode_udp(ethpkt, myudpheader)

            offset = eth_length + ip_length + udp_length + vxlan_length
            decode_nsh_baseheader(ethpkt, offset, mynshbaseheader)
            decode_nsh_contextheader(ethpkt, offset + nshbase_length, mynshcontextheader)
        elif (args.type == "vxlan"):
            """ Decode IP header """
            decode_ip(ethpkt, myipheader)

            """ Decode UDP header """
            decode_udp(ethpkt, myudpheader)

        pktnum = 0
        while (args.number > 0):
            """ Send it and make sure all the data is sent out """
            pkt = ethpkt
            while pkt:
                sent = send_s.send(pkt)
                args.number -= 1
                pkt = pkt[sent:]
            pktnum += 1
            if (do_print):
                print("\n\nSent Packet #%d" % pktnum)

            """ Print ethernet header """
            if (do_print):
                print_ethheader(myethheader)

            if (do_print):
                print_ipheader(myipheader)
                
            if (do_print):
                print_udpheader(myudpheader)

            if (args.type == "vxlan_gpe_nsh"):
                """ Print IP header """
                if (do_print):
                    print_ipheader(myipheader)

                """ Print UDP header """
                if (do_print):
                    print_udpheader(myudpheader)

                """ Print VxLAN/VxLAN-gpe header """
                if (do_print):
                    print_vxlanheader(myvxlanheader)

                """ Print NSH base header """
                if (do_print):
                    print_nsh_baseheader(mynshbaseheader)

                if (do_print):
                    print_nsh_md2(md2)

                """ Print NSH context header """
                if (do_print):
                    print_nsh_contextheader(mynshcontextheader)

        sys.exit(0)

#
# cmd:
# python vxlan_tools_supported_ipv6.py -i vxlan.eth1 -d send --type vxlan -iipv 6 --outer-source-mac ${s_mac} --outer-source-ip ${s_ip} --outer-destination-mac ${d_mac} --outer-destination-ip ${d_ip} --inner-source-mac ... --inner-source-ip ... --inner-destination-mac ... --inner-destination-ip -n 1
#
if __name__ == "__main__":
    main()
