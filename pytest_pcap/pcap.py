from __future__ import division, absolute_import
import struct
import socket
from ._pcap import ffi, lib


version = ffi.string(lib.pcap_lib_version())

MAXIMUM_SNAPLEN = 262144

DLT_EN10MB = lib.DLT_EN10MB
DLT_LINUX_SLL = lib.DLT_LINUX_SLL

ETH_P_IP = lib.ETH_P_IP
ETH_P_ARP = lib.ETH_P_ARP
ETH_P_IPV6 = lib.ETH_P_IPV6


def unwrap_datalink(datalink, data):
    if datalink == DLT_EN10MB:
        return Ethernet(data)
    elif datalink == DLT_LINUX_SLL:
        return LinuxSLL(data)


def unwrap_network(next_header, data):
    if next_header == ETH_P_IP:
        return IP(data)
    elif next_header == ETH_P_IPV6:
        return IPV6(data)


def unwrap_transport(next_header, data):
    if next_header == socket.IPPROTO_TCP:
        return TCP(data)
    elif next_header == socket.IPPROTO_UDP:
        return UDP(data)


class Ethernet(object):
    hdr = struct.Struct('!6s6sH')

    def __init__(self, data):
        header = Ethernet.hdr.unpack(data[:Ethernet.hdr.size])
        self.header = {'dest': header[0],
                       'source': header[1],
                       'proto': header[2]}
        self.data = data[Ethernet.hdr.size:]
        self.upper = unwrap_network(self.next_header, self.data)

    @property
    def next_header(self):
        proto = self.header['proto']
        # Determine if we're an Ethernet II or IEEE 802.3 packet
        if proto >= 1500:
            return proto

    def __str__(self):
        return str(self.upper) if self.upper else 'UNKNOWN'


class LinuxSLL(object):
    # +---------------------------+
    # |         Packet type       |
    # |         (2 Octets)        |
    # +---------------------------+
    # |        ARPHRD_ type       |
    # |         (2 Octets)        |
    # +---------------------------+
    # | Link-layer address length |
    # |         (2 Octets)        |
    # +---------------------------+
    # |    Link-layer address     |
    # |         (8 Octets)        |
    # +---------------------------+
    # |        Protocol type      |
    # |         (2 Octets)        |
    # +---------------------------+
    hdr = struct.Struct('!HHH8sH')

    def __init__(self, data):
        header = LinuxSLL.hdr.unpack(data[:LinuxSLL.hdr.size])
        self.header = {'sll_pkttype': header[0],
                       'sll_hatype': header[1],
                       'sll_halen': header[2],
                       'sll_addr': header[3],
                       'sll_protocol': header[4]}
        self.data = data[LinuxSLL.hdr.size:]
        self.upper = unwrap_network(self.next_header, self.data)

    @property
    def next_header(self):
        proto = self.header['sll_protocol']
        if proto >= 1500:
            return proto

    def __str__(self):
        return str(self.upper) if self.upper else 'UNKNOWN'


class IP(object):
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |Version|  IHL  |Type of Service|          Total Length         |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |         Identification        |Flags|      Fragment Offset    |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |  Time to Live |    Protocol   |         Header Checksum       |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                       Source Address                          |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                    Destination Address                        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                    Options                    |    Padding    |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    hdr = struct.Struct('!BBHHHBBH4s4s')

    def __init__(self, data):
        header = IP.hdr.unpack(data[:IP.hdr.size])
        self.header = {'ip_hl': header[0] & 0x0F,
                       'ip_v': header[0] >> 4,
                       'ip_tos': header[1],
                       'ip_len': header[2],
                       'ip_id': header[3],
                       'ip_off': header[4],
                       'ip_ttl': header[5],
                       'ip_p': header[6],
                       'ip_sum': header[7],
                       'ip_src': header[8],
                       'ip_dst': header[9]}
        self.data = data[self.header['ip_hl'] * 4:]
        self.upper = unwrap_transport(self.next_header, self.data)

    @property
    def next_header(self):
        return self.header['ip_p']

    @property
    def src(self):
        return socket.inet_ntop(socket.AF_INET, self.header['ip_src'])

    @property
    def dst(self):
        return socket.inet_ntop(socket.AF_INET, self.header['ip_dst'])

    @property
    def flags(self):
        return (self.header['ip_off'] & 0xE000) >> 13

    def __str__(self):
        if self.upper:
            return ': '.join((
                'IP {}:{} > {}:{}'.format(self.src, self.upper.srcport,
                                          self.dst, self.upper.dstport),
                str(self.upper)
            ))
        return 'IP {} > {}: UNKNOWN'.format(self.src, self.dst)


class IPV6(object):
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |Version| Traffic Class |           Flow Label                  |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |         Payload Length        |  Next Header  |   Hop Limit   |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                                                               |
    # +                                                               +
    # |                                                               |
    # +                         Source Address                        +
    # |                                                               |
    # +                                                               +
    # |                                                               |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                                                               |
    # +                                                               +
    # |                                                               |
    # +                      Destination Address                      +
    # |                                                               |
    # +                                                               +
    # |                                                               |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    hdr = struct.Struct('!IHBB16s16s')

    def __init__(self, data):
        header = IPV6.hdr.unpack(data[:IPV6.hdr.size])
        # Make sure the ipv6 version field has the right magic number
        assert header[0] >> 24 == 0x60
        self.header = {'ip6_flow': header[0] & 0x0fffffff,
                       'ip6_plen': header[1],
                       'ip6_nxt': header[2],
                       'ip6_hlim': header[3],
                       'ip6_src': header[4],
                       'ip6_dst': header[5]}
        self.data = data[IPV6.hdr.size:]
        self.upper = unwrap_transport(self.next_header, self.data)

    @property
    def next_header(self):
        return self.header['ip6_nxt']

    @property
    def src(self):
        return socket.inet_ntop(socket.AF_INET6, self.header['ip6_src'])

    @property
    def dst(self):
        return socket.inet_ntop(socket.AF_INET6, self.header['ip6_dst'])

    def __str__(self):
        if self.upper:
            return ': '.join((
                'IPV6 [{}]:{} > [{}]:{}'.format(self.src, self.upper.srcport,
                                                self.dst, self.upper.dstport),
                str(self.upper)
            ))
        return 'IPV6 {} > {}: UNKNOWN'.format(self.src, self.dst)


class TCP(object):
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |          Source Port          |       Destination Port        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                        Sequence Number                        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                    Acknowledgment Number                      |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |  Data |           |U|A|P|R|S|F|                               |
    # | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
    # |       |           |G|K|H|T|N|N|                               |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |           Checksum            |         Urgent Pointer        |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                    Options                    |    Padding    |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                             data                              |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    hdr = struct.Struct('!HHLLBBHHH')

    def __init__(self, data):
        header = TCP.hdr.unpack(data[:TCP.hdr.size])
        self.header = {'source': header[0],
                       'dest': header[1],
                       'seq': header[2],
                       'ack_seq': header[3],
                       'off': header[4] >> 4,
                       'flags': header[5]}
        self.data = data[self.header['off'] * 4:]

    @property
    def srcport(self):
        return self.header['source']

    @property
    def dstport(self):
        return self.header['dest']

    def __str__(self):
        return 'TCP'


class UDP(object):
    #  0      7 8     15 16    23 24    31
    # +--------+--------+--------+--------+
    # |     Source      |   Destination   |
    # |      Port       |      Port       |
    # +--------+--------+--------+--------+
    # |                 |                 |
    # |     Length      |    Checksum     |
    # +--------+--------+--------+--------+
    # |
    # |          data octets ...
    # +---------------- ...
    hdr = struct.Struct('!HHHH')

    def __init__(self, data):
        header = UDP.hdr.unpack(data[:UDP.hdr.size])
        self.header = {'source': header[0],
                       'dest': header[1],
                       'len': header[2],
                       'sum': header[3]}
        self.data = data[UDP.hdr.size:]

    @property
    def srcport(self):
        return self.header['source']

    @property
    def dstport(self):
        return self.header['dest']

    def __str__(self):
        return 'UDP'


class PcapError(Exception):
    @classmethod
    def fromhandle(cls, handle):
        err = lib.pcap_geterr(handle)
        return cls(ffi.string(err))


@ffi.def_extern()
def dumper_dispatch(user, header, data):
    handle = ffi.cast('void*', user)
    ffi.from_handle(handle).write(header, data)


class Dumper(object):
    def __init__(self, handle, filename):
        self.handle = handle
        self.dumpfile = lib.pcap_dump_open(self.handle, filename.encode())
        if not self.dumpfile:
            raise PcapError.fromhandle(self.handle)

    def close(self):
        lib.pcap_dump_close(self.dumpfile)
        self.dumpfile = None

    def dispatch(self, count=-1):
        return lib.pcap_dispatch(self.handle, count, lib.dumper_dispatch,
                                 ffi.new_handle(self))

    def write(self, header, data):
        dumpfile = ffi.cast('u_char*', self.dumpfile)
        lib.pcap_dump(dumpfile, header, data)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class Pcap(object):
    errbuf = ffi.new('char[]', lib.PCAP_ERRBUF_SIZE)

    def __init__(self, handle):
        self.handle = handle

    @staticmethod
    def lookupdev():
        dev = lib.pcap_lookupdev(Pcap.errbuf)
        if not dev:
            raise PcapError(ffi.string(Pcap.errbuf))
        return ffi.string(dev)

    @classmethod
    def open_live(cls, device, snaplen, promisc, to_ms):
        handle = lib.pcap_create(device.encode(), Pcap.errbuf)
        if handle == ffi.NULL:
            raise PcapError(ffi.string(Pcap.errbuf))
        if lib.pcap_set_snaplen(handle, snaplen) < 0:
            raise PcapError.fromhandle(handle)
        if lib.pcap_set_promisc(handle, promisc) < 0:
            raise PcapError.fromhandle(handle)
        if lib.pcap_set_timeout(handle, to_ms) < 0:
            raise PcapError.fromhandle(handle)
        if lib.pcap_activate(handle):
            raise PcapError.fromhandle(handle)

        return cls(handle)

    @classmethod
    def open_offline(cls, filename):
        handle = lib.pcap_open_offline_with_tstamp_precision(
            filename.encode(),
            lib.PCAP_TSTAMP_PRECISION_MICRO,
            Pcap.errbuf
        )
        if not handle:
            raise PcapError(ffi.string(Pcap.errbuf))

        return cls(handle)

    def close(self):
        lib.pcap_close(self.handle)
        self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def dumper(self, filename):
        return Dumper(self.handle, filename)

    def setfilter(self, program):
        bpf = ffi.new('struct bpf_program*')
        if lib.pcap_compile(self.handle, bpf, program, 1,
                            lib.PCAP_NETMASK_UNKNOWN) == -1:
            raise PcapError.fromhandle(self.handle)

        if lib.pcap_setfilter(self.handle, bpf) == -1:
            raise PcapError.fromhandle(self.handle)

    @property
    def nonblocking(self):
        ret = lib.pcap_getnonblock(self.handle, self.errbuf)
        if ret == -1:
            raise PcapError(ffi.string(self.errbuf))
        return bool(ret)

    @nonblocking.setter
    def nonblocking(self, value):
        ret = lib.pcap_setnonblock(self.handle, value, self.errbuf)
        if ret == -1:
            raise PcapError(ffi.string(self.errbuf))

    def fileno(self):
        return lib.pcap_get_selectable_fd(self.handle)

    @property
    def stats(self):
        stats = ffi.new('struct pcap_stat*')
        if lib.pcap_stats(self.handle, stats) == -1:
            raise PcapError.fromhandle(self.handle)
        return stats.ps_recv, stats.ps_drop, stats.ps_ifdrop

    @property
    def datalink(self):
        return lib.pcap_datalink(self.handle)

    def packets(self):
        datalink = self.datalink
        header = ffi.new('struct pcap_pkthdr**')
        data = ffi.new('u_char**')

        assert datalink in (DLT_EN10MB, DLT_LINUX_SLL)

        while True:
            res = lib.pcap_next_ex(self.handle, header, data)
            if res == 1:
                ts = header[0].ts
                yield (ts.tv_sec + ts.tv_usec / 1000000,
                       unwrap_datalink(datalink,
                                       ffi.buffer(data[0], header[0].len)))
            elif res == 0:
                continue
            elif res == -1:
                raise PcapError.fromhandle(self.handle)
            elif res == -2:
                break
