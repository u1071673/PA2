# Author: John Young
# Date:   3-19-2019
# Course: CS 4480, University of Utah, School of Computing
# Copyright: CS 4480 and John Young - This work may not be copied for use in Academic Coursework.
#
# I, John Young, certify that I wrote this code from scratch and did not copy it in part or whole from
# another source.  Any references used in the completion of the assignment are cited in my README file.
#
# File Contents
#
#    This is the main monitor file for PA2. For Phase 2 this file just prints informatio about ARP and ICMP packets.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0, ofproto_v1_2, ofproto_v1_3, ofproto_v1_4, ofproto_v1_5
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import arp
from ryu.lib.packet import icmp
from ryu.lib.packet import icmpv6
from ryu.lib.packet import ether_types
from array import array

class Monitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # Number of ARP and ICMP packet protocols received.
    pkts_received = 0

    def __init__(self, *args, **kwargs):
        '''
        Init method that calls the super init method of Monitor.
        :param args: Init arguments
        :param kwargs: Init KW arguments
        '''
        super(Monitor, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    # Inspired by https://github.com/osrg/ryu/blob/master/ryu/app/simple_switch_13.py
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        '''
        Called during the CONFIG_DISPATCHER phase to setup the first entry into the switch's OF table.
        After setting up the OF entry it's then added into the switch's OF table.
        :param ev: The event that triggered EventOFPSwitchFeatures, during CONFIG_DISPATCHER.
        Carries information about the state of the switch.
        :return: N/A
        '''
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow_entry_to_switch(datapath, 0, match, actions)

    # Inspired by https://github.com/osrg/ryu/blob/master/ryu/app/simple_switch_13.py
    def add_flow_entry_to_switch(self, datapath, priority, match, actions, buffer_id=None):
        '''
        Adds an open flow entry to the table using a OFPFlowMod outgoing packet.
        :param datapath: The OF entry's datapath
        :param priority: The OF entry's priority
        :param match: The OF entry's match address range
        :param actions: The OF entry's action to do on match
        :param buffer_id: The OF entry's buffer id
        :return: N/A
        '''
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)

        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        '''
        Handles packets that are coming in during the MAIN_DISPATCHER phase.
        :param ev: The event that triggered EventOFPPacketIn, durign MAIN_DISPATCHER.
        It also carries the information about the state of the switch.
        :return: N/A
        '''
        msg = ev.msg
        self.print_packet_arp_icmp(msg)

    # Inspired by https://ryu.readthedocs.io/en/latest/library_packet.html
    def print_packet_arp_icmp(self, msg):
        '''
        Prints packets that follow protocols ARP or ICMP.
        :param msg: The msg containing a packet to search and print
        :return: N/A
        '''
        in_port = '?'
        for name, value in msg.match._fields2:
            if name == 'in_port':
                in_port = str(value)
        print_header = 'Packet('+ str(self.pkts_received) + ') Received on Port(' + str(in_port)+ '):'
        print_body = ''

        pkt = packet.Packet(bytearray(msg.data))

        # Example {ethernet} ethernet(dst='33:33:ff:00:00:03',ethertype=34525,src='00:00:00:00:00:03')
        ethernet_pkt = pkt.get_protocol(ethernet.ethernet)
        # Example {ipv4} ipv4(csum=43378,dst='10.0.0.3',flags=2,header_length=5,identification=32051,offset=0,option=None,proto=1,src='10.0.0.1',tos=0,total_length=84,ttl=64,version=4)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        # Example # {ipv6} ipv6(dst='ff02::16',ext_hdrs=[hop_opts(data=[option(data=b'\x00\x00',len_=2,type_=5), option(data=None,len_=0,type_=1)],nxt=58,size=0)],flow_label=0,hop_limit=1,nxt=0,payload_length=56,src='::',traffic_class=0,version=6)
        ipv6_pkt = pkt.get_protocol(ipv6.ipv6)
        # Example {arp} arp(dst_ip='10.0.0.1',dst_mac='00:00:00:00:00:00',hlen=6,hwtype=1,opcode=1,plen=4,proto=2048,src_ip='10.0.0.3',src_mac='00:00:00:00:00:03')
        arp_pkt = pkt.get_protocol(arp.arp)
        # Example icmp(code=0,csum=57873,data=echo(data=bytearray(b'dl\x94\\\x00\x00\x00\x00\r\x9e\x06\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !"#$%&\'()*+,-./01234567'),id=19123,seq=1),type=8)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        # Example {icmpv6} icmpv6(code=0,csum=39570,data=mldv2_report(record_num=2,records=[mldv2_report_group(address='ff02::1:ff69:d373',aux=None,aux_len=0,num=0,srcs=[],type_=3), mldv2_report_group(address='ff02::1:ff00:1',aux=None,aux_len=0,num=0,srcs=[],type_=4)]),type_=143)
        icmpv6_pkt = pkt.get_protocol(icmpv6.icmpv6)

        if ethernet_pkt:
            print_body += """ETH
    From MAC: """ + str(ethernet_pkt.src) + """
    To   MAC: """ + str(ethernet_pkt.dst) + """
"""
            print_header += ' ETH'

        if ipv4_pkt:
            print_body += """IPV4
    Version:  """ + str(ipv4_pkt.version) + """
    Check Sum:""" + str(ipv4_pkt.csum) + """
    From IP:  """ + str(ipv4_pkt.src) + """
    To IP:    """ + str(ipv4_pkt.dst) + """
    Length:   """ + str(ipv4_pkt.total_length) + """
"""
        else:
            print_body += 'NOT IPV4\n'

        if ipv6_pkt:
            print_body += """IPv6
    Version:  """ + str(ipv6_pkt.version) + """
    From IP:  """ + str(ipv6_pkt.src) + """
    To IP:    """ + str(ipv6_pkt.dst) + """
    Length:   """ + str(ipv6_pkt.payload_length) + """
"""
        else:
            print_body += 'NOT IPV6\n'

        if arp_pkt:
            print_body += """ARP
    From IP:  """ + str(arp_pkt.src_ip) + """
    To   IP:  """ + str(arp_pkt.dst_ip) + """
    From MAC: """ + str(arp_pkt.src_mac) + """
    To   MAC: """ + str(arp_pkt.dst_mac) + """
"""
            print_header += ' ARP'

        if icmp_pkt:
            print_body += """PING
"""
            print_header += ' PING'

        (cntl_address, cntl_port) = msg.datapath.address

        for protocol in pkt.protocols:
            if protocol.protocol_name != 'arp' and protocol.protocol_name != 'ethernet' and protocol.protocol_name != 'icmp' and protocol.protocol_name != 'ipv4' and protocol.protocol_name != 'ipv6':
                print_header += " " + protocol.protocol_name.upper()
                print_body += """""" + protocol.protocol_name.upper() + """
"""

        print_body += """Controller (OF)
    Address, Port: (\'""" + str(cntl_address) + """\', """ + str(cntl_port) + """)"""

        print("""----------------------------------------------
""" + print_header + """
""" + print_body + """""")

        # Increment packet counter
        self.pkts_received += 1
