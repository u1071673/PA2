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

from array import array
from ryu import cfg
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import arp
from ryu.lib.packet import icmp
from ryu.lib.packet import icmpv6
from ryu.lib.packet import ether_types
from ryu.ofproto import ofproto_v1_3
import config

class Monitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        '''
        Init method that calls the super init method of Monitor.
        :param args: Init arguments
        :param kwargs: Init KW arguments
        '''
        super(Monitor, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        # Number of ARP and ICMP packet protocols received.
        self.pkts_received = 0

        # Inspired by https://stackoverflow.com/questions/17424905/passing-own-arguments-to-ryu-proxy-app
        CONF = cfg.CONF
        CONF.register_opts([
            cfg.IntOpt('front_end_testers', default=4, help = ('Number of Front End Testers')),
            cfg.IntOpt('back_end_servers', default=2, help = ('Number of Back End Testers')),
            cfg.StrOpt('virtual_ip', default='10.0.0.10', help = ('Virtual IP address'))
        ])

        self.front_end_testers = CONF.front_end_testers
        self.back_end_servers = CONF.back_end_servers
        self.virtual_ip = CONF.virtual_ip
        self.next_out = self.front_end_testers

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
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        OFPP_CONTROLLER = ofproto.OFPP_CONTROLLER
        OFPCML_NO_BUFFER = ofproto.OFPCML_NO_BUFFER
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(OFPP_CONTROLLER, OFPCML_NO_BUFFER)]
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
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        OFPIT_APPLY_ACTIONS = ofproto.OFPIT_APPLY_ACTIONS
        instructions = [parser.OFPInstructionActions(OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match,
                                    instructions=instructions)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=instructions)

        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        '''
        Handles packets that are coming in during the MAIN_DISPATCHER phase.
        :param ev: The event that triggered EventOFPPacketIn, durign MAIN_DISPATCHER.
        It also carries the information about the state of the switch.
        :return: N/A
        '''
        # Message Size Check.
        msg = ev.msg
        msg_len = msg.msg_len
        total_len = msg.total_len

        if msg_len < total_len:
            self.logger.debug("Message length is %s, which is larger than the full length frame size of %s bytes. "
                              "Consider increasing 'miss_send_length' of the Mininet switch.", msg_len, total_len)

        if config.verbose:
            self.print_packet(msg)

        self.packet_out(msg)

    # Inspired by https://github.com/osrg/ryu/blob/master/ryu/app/simple_switch_13.py
    def packet_out(self, msg):
        '''
        Parses a msg and adds a flow entry when applicable, then sends the message
        out to the desired destination.
        :param msg: Message containing packet info.
        :return: N/A
        '''
        in_port = msg.match['in_port']
        buffer_id = msg.buffer_id
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        switch_id = datapath.id
        OFP_NO_BUFFER = ofproto.OFP_NO_BUFFER
        OFPP_FLOOD = ofproto.OFPP_FLOOD

        pkt = packet.Packet(msg.data)
        ethernet_pkt = pkt.get_protocol(ethernet.ethernet)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        ipv6_pkt = pkt.get_protocol(ipv6.ipv6)
        arp_pkt = pkt.get_protocol(arp.arp)

        dst = ethernet_pkt.dst
        src = ethernet_pkt.src

        # Ignore LDDP packet because it is just a device advertising it's ID.
        if ethernet_pkt.ethertype == ether_types.ETH_TYPE_LLDP:
            self.logger.debug('Ignoring LLDP packet.')
            return

        self.logger.info('Switch %s @ port %s says that %s is looking for %s.', switch_id, in_port, src, dst)
        self.mac_to_port.setdefault(switch_id, {})

        # void FLOOD
        self.mac_to_port[switch_id][src] = in_port
        if dst in self.mac_to_port[switch_id]:
            out_port = self.mac_to_port[switch_id][dst]
        elif arp_pkt and arp_pkt.dst_ip == msg.self.virtual_ip:
            out_port = self.next_out_port()
        else
            out_port = OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        # Install a flow packet_in
        if out_port != OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # Verify if we have a valid buffer_id, if yes avoid to send both flow_mod & packet_out
            if msg.buffer_id == OFP_NO_BUFFER:
                # Not a valid buffer_id, so sending out a flow_mod and continuing to generate a packet_out
                self.add_flow_entry_to_switch(datapath, 1, match, actions)
            else:
                # We already have a valid buffer_id so only send out flow_mod then return.
                self.add_flow_entry_to_switch(datapath, 1, match, actions, buffer_id)
                return

        if buffer_id == OFP_NO_BUFFER: # Only send msg data when protocol is OFP_NO_BUFFER
            data = msg.data
        else:
            data = None

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id, in_port=in_port, actions=actions, data=data)

        datapath.send_msg(out)

    next_out = 0;
    def next_out_port(self):
        '''
        Generates the next_port out based on last port assigned to machine.
        :return: Next port to assign.
        '''
        next_port_out = self.next_out
        self.next_out++
        if self.next_out >= (self.front_end_testers + self.back_end_servers):
            self.next_out = self.front_end_testers
        return self.next_out =  % (self.front_end_testers + self.back_end_servers)

    # Inspired by https://ryu.readthedocs.io/en/latest/library_packet.html
    def print_packet(self, msg):
        '''
        Prints packets that follow protocols ARP or ICMP.
        :param msg: The msg containing a packet to search and print
        :return: N/A
        '''
        in_port = msg.match['in_port']
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