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
from re import findall
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
from ryu.ofproto import ether

import netaddr

class Monitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        '''
        Init method that calls the super init method of Monitor.
        :param args: Init arguments
        :param kwargs: Init KW arguments
        '''
        super(Monitor, self).__init__(*args, **kwargs)
        self.ip_to_port = {}
        self.client_to_server = {}
        self.mac_port_from_ip = {}

        # Number of ARP and ICMP packet protocols received (received packets counter)
        self.pkts_received = 0

        # Inspired by https://stackoverflow.com/questions/17424905/passing-own-arguments-to-ryu-proxy-app
        CONF = cfg.CONF
        CONF.register_opts([
            cfg.IntOpt('front_end_testers', default=4, help = ('Number of Front End Testers')),
            cfg.IntOpt('back_end_servers', default=2, help = ('Number of Back End Testers')),
            cfg.StrOpt('virtual_ip', default='10.0.0.10', help = ('Virtual IP address'))
        ])

        # Using config file variables.
        self.front_end_testers = CONF.front_end_testers
        self.back_end_servers = CONF.back_end_servers
        self.virtual_ip = CONF.virtual_ip
        self.next_out = self.front_end_testers + 1

        self.logger.info("Configured for %s testers and %s servers located at %s virtual ip address.",
                         self.front_end_testers, self.back_end_servers, self.virtual_ip)
        self.logger.info("First server located at port %s", self.next_out)

    # Inspired by https://github.com/osrg/ryu/blob/master/ryu/app/simple_switch_13.py
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        '''
        Called during the CONFIG_DISPATCHER phase to setup the first entry into the switch's OF table.
        After setting up the OF entry it's then added into the switch's OF table.
        :param ev: The event that triggered EventOFPSwitchFeatures, during CONFIG_DISPATCHER.
        Carries information about the state of the switch.
        '''
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        OFPP_CONTROLLER = ofproto.OFPP_CONTROLLER
        OFPCML_NO_BUFFER = ofproto.OFPCML_NO_BUFFER
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(OFPP_CONTROLLER, OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    # Inspired by https://github.com/osrg/ryu/blob/master/ryu/app/simple_switch_13.py
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
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
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=instructions)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=instructions)

        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        '''
        Handles packets that are coming in during the MAIN_DISPATCHER phase.
        :param ev: The event that triggered EventOFPPacketIn, durign MAIN_DISPATCHER.
        It also carries the information about the state of the switch.
        '''
        msg = ev.msg
        self.print_packet(msg)
        self.packet_out(msg)

    # Inspired by https://github.com/osrg/ryu/blob/master/ryu/app/simple_switch_13.py
    def packet_out(self, msg):
        '''
        Parses a msg and adds a flow entry when applicable, then sends the message
        out to the desired destination.
        :param msg: Message containing packet info.
        '''
        data = msg.data
        pkt = packet.Packet(data)
        ethernet_pkt = pkt.get_protocol(ethernet.ethernet)
        # Ignore LDDP packet because it is just a device advertising it's ID.
        if ethernet_pkt.ethertype == ether_types.ETH_TYPE_LLDP:
            self.logger.debug('Ignoring LLDP packet.')
            return

        in_port = msg.match['in_port']
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        switch_id = datapath.id
        OFPP_FLOOD = ofproto.OFPP_FLOOD

        self.ip_to_port.setdefault(switch_id, {})
        self.client_to_server.setdefault(switch_id, {})
        self.mac_port_from_ip.setdefault(switch_id, {})

        arp_pkt = pkt.get_protocol(arp.arp)

        dst_mac = ethernet_pkt.dst
        src_mac = ethernet_pkt.src

        if arp_pkt and arp_pkt.opcode == arp.ARP_REQUEST:
            src_ip = arp_pkt.src_ip

            if arp_pkt.dst_ip == self.virtual_ip:
                needs_init = src_ip not in self.client_to_server[switch_id]
                dst_mac, dst_ip, out_port = self.next_mac_ip_port(switch_id=switch_id, src_ip=src_ip)
                src_ip = arp_pkt.src_ip

                if needs_init:
                    self.client_to_server[switch_id][src_ip] = dst_mac, dst_ip, out_port
                    self.mac_port_from_ip[switch_id][src_ip] = src_mac, in_port
                    self.add_two_way_flow(parser=parser, datapath=datapath,
                                          src_ip=src_ip, dst_ip=dst_ip, in_port=in_port,
                                          out_port=out_port)

                # Send ARP reply to host
                out = self.build_arp(datapath=datapath, opcode=arp.ARP_REPLY, parser=parser,
                                     ip_of_interest=self.virtual_ip, mac_of_interest=dst_mac, port_of_interest=out_port,
                                     ip_to_tell=src_ip, mac_to_tell=src_mac, port_to_tell=in_port)
                datapath.send_msg(out)


            elif arp_pkt.dst_ip in self.client_to_server[switch_id]:
                src_mac, src_ip, in_port = self.client_to_server[switch_id][arp_pkt.dst_ip]
                dst_mac, out_port = self.mac_port_from_ip[switch_id][arp_pkt.dst_ip]
                dst_ip = arp_pkt.dst_ip

                # Send ARP reply to server
                out = self.build_arp(datapath=datapath, opcode=arp.ARP_REPLY, parser=parser,
                                     ip_of_interest=arp_pkt.dst_ip, mac_of_interest=dst_mac, port_of_interest=out_port,
                                     ip_to_tell=src_ip, mac_to_tell=src_mac, port_to_tell=in_port)
                datapath.send_msg(out)


    # Inspired by https://stackoverflow.com/questions/46697490/converting-hex-number-to-mac-address#46697810
    def port_to_mac(self, port: int):
        '''
        Generates a mac address from a given port. (i.e port=5 to mac=00:00:00:00:00:05)
        :param port: The port number to generate a mac address for.
        :return: The mac address that is generated from the port.
        '''
        mac_address = '{0:012x}'.format(port)
        mac_address = ':'.join(findall(r'\w\w', mac_address))
        return mac_address

    def port_to_ip(self, port: int):
        '''
        Generates a ip address from a given port. (i.e port=5 to ip=0.0.0.5)
        :param port: The port number to generate a ip address for.
        :return: The ip address that is generated from the port.
        '''
        byte0 = 255 if port > 255 * 1 else (0 if port < 255 * 0 else port - (255 * 0))
        byte1 = 255 if port > 255 * 2 else (0 if port < 255 * 1 else port - (255 * 1))
        byte2 = 255 if port > 255 * 3 else (0 if port < 255 * 2 else port - (255 * 2))
        byte3 = 10
        return str(str(byte3) + str('.') + str(byte2) + str('.') + str(byte1) + str('.') + str(byte0))

    def next_mac_ip_port(self, switch_id, src_ip):
        '''
        Generates the next_port out, in round robbin fashion, based on last port assigned to machine.
        :return: A tuple containing the <str, str, int> mac, ip, port.
        '''

        if src_ip in self.ip_to_port[switch_id]:
            out_port = self.ip_to_port[switch_id][src_ip]
        else:
            if self.next_out > (self.front_end_testers + self.back_end_servers):
                self.next_out = self.front_end_testers + 1

            out_port = self.next_out
            self.ip_to_port[switch_id][src_ip] = out_port
            self.next_out += 1

        dst_mac = self.port_to_mac(out_port)
        dst_ip = self.port_to_ip(out_port)

        return (dst_mac, dst_ip, out_port)

    def add_two_way_flow(self, parser, datapath, src_ip, dst_ip, in_port, out_port):
        self.logger.info('Adding OF rule [' + self.virtual_ip + ' -> ' + src_ip + '] to s1')
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                ipv4_dst=src_ip, ipv4_src=dst_ip)
        actions = [parser.OFPActionOutput(in_port)]
        self.add_flow(datapath, 1, match, actions, buffer_id=ofproto_v1_3.OFP_NO_BUFFER)

        self.logger.info('Adding OF rule [' + src_ip + ' -> ' + self.virtual_ip + '] to s1')
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                ipv4_dst=self.virtual_ip, ipv4_src=src_ip)
        actions = [parser.OFPActionSetField(ipv4_dst=dst_ip), parser.OFPActionOutput(out_port)]
        self.add_flow(datapath, 1, match, actions, buffer_id=ofproto_v1_3.OFP_NO_BUFFER)

    def build_arp(self, datapath, parser, opcode, ip_of_interest, mac_of_interest, port_of_interest, ip_to_tell, mac_to_tell, port_to_tell):
        '''

        :param datapath:
        :param parser:
        :param opcode:
        :param ip_of_interest: IP to add to ARP table
        :param mac_of_interest: MAC to add to ARP table
        :param port_of_interest: Port to add to ARP table
        :param ip_to_tell: IP of machine being added to.
        :param mac_to_tell: MAC of machine being added to.
        :param port_to_tell: port of machine being added to.
        :return:
        '''
        '''
        Generates an ARP reply packet.

        ARP reply Example parser.OFPPacketOut parameter values:
        simple_switch_13  -> h1 ping -c 1 h3
        simple_switch_13  -> ethernet(dst='00:00:00:00:00:01',ethertype=2054,src='00:00:00:00:00:03')
        simple_switch_13  -> arp(dst_ip='10.0.0.1',dst_mac='00:00:00:00:00:01',hlen=6,hwtype=1,opcode=2,plen=4,proto=2048,src_ip='10.0.0.3',src_mac='00:00:00:00:00:03')
        simple_switch_13  -> actions = <class 'list'>: [OFPActionOutput(len=16,max_len=65509,port=1,type=0)]
        simple_switch_13  -> in_port = 3
        simple_switch_13  -. data = b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x03\x08\x06\x00\x01\x08\x00\x06\x04\x00\x02\x00\x00\x00\x00\x00\x03\n\x00\x00\x03\x00\x00\x00\x00\x00\x01\n\x00\x00\x01'
        monitor           -> h1 ping -c 1 10.0.0.10
        monitor           -> ethernet(dst='00:00:00:00:00:01',ethertype=2054,src='00:00:00:00:00:05')
        monitor           -> arp(dst_ip='10.0.0.1',dst_mac='00:00:00:00:00:01',hlen=6,hwtype=1,opcode=2,plen=4,proto=2048,src_ip='10.0.0.10',src_mac='00:00:00:00:00:05')
        monitor           -> actions = <class 'list'>: [OFPActionOutput(len=16,max_len=65509,port=1,type=0)]
        monitor           -> in_port = 5
        monitor           -> data = b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x03\x08\x06\x00\x01\x08\x00\x06\x04\x00\x02\x00\x00\x00\x00\x00\x03\n\x00\x00\x03\x00\x00\x00\x00\x00\x01\n\x00\x00\x01'
        :param datapath: 
        :param src_mac:
        :param src_ip:
        :param dst_mac:
        :param dst_ip:
        :param in_port:
        :param out_port:
        :return:
        '''

        if opcode == arp.ARP_REPLY:
            self.logger.info('ARP Reply, ' + str(ip_of_interest) + ' is at ' + str(mac_of_interest) + ' for ' + str(ip_to_tell))
        elif opcode == arp.ARP_REQUEST:
            self.logger.info('ARP Request, who-has ' + str(ip_to_tell) + ' tell ' + str(ip_of_interest))

        p = packet.Packet()

        p.add_protocol(ethernet.ethernet(dst=mac_to_tell, src=mac_of_interest, ethertype=ether.ETH_TYPE_ARP))
        p.add_protocol(arp.arp(hwtype=1, proto=ether.ETH_TYPE_IP, hlen=6, plen=4, opcode=opcode,
                               src_mac=mac_of_interest, src_ip=ip_of_interest,
                               dst_mac=mac_to_tell, dst_ip=ip_to_tell))

        p.serialize()
        data = p.data

        actions = [parser.OFPActionOutput(port_to_tell)]

        arp_msg = parser.OFPPacketOut(datapath=datapath, in_port=port_of_interest, actions=actions, data=data,
                                  buffer_id=ofproto_v1_3.OFP_NO_BUFFER)

        return arp_msg

        # Inspired by https://ryu.readthedocs.io/en/latest/library_packet.html
    def print_packet(self, msg):
        '''
        Prints information about the packet's message and increments the received packets counter.
        :param msg: The msg containing a packet to search and print
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
        # Example {icmp} icmp(code=0,csum=57873,data=echo(data=bytearray(b'dl\x94\\\x00\x00\x00\x00\r\x9e\x06\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !"#$%&\'()*+,-./01234567'),id=19123,seq=1),type=8)
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
    Opcode:   """ + str(arp_pkt.opcode) + """
"""
            print_header += ' ARP'

        if icmp_pkt:
            print_body += 'ICMP'
            if icmp_pkt.code == 0 and (icmp_pkt.type == 8 or icmp_pkt.type == 0):
                print_body += ' PING'
                print_header += ' PING'
            else:
                print_header += ' ICMP'

            print_body += """
    Code:       """ + str(icmp_pkt.code) + """
    Check Sum:  """ + str(icmp_pkt.csum) + """
    Type:       """ + str(icmp_pkt.type) + """
"""

        (cntl_address, cntl_port) = msg.datapath.address

        for protocol in pkt.protocols:
            if protocol.protocol_name != 'arp' and protocol.protocol_name != 'ethernet' and protocol.protocol_name != 'icmp' and protocol.protocol_name != 'ipv4' and protocol.protocol_name != 'ipv6':
                print_header += " " + protocol.protocol_name.upper()
                print_body += """""" + protocol.protocol_name.upper() + """
"""

        print_body += """Controller (OF)
    Address, Port: (\'""" + str(cntl_address) + """\', """ + str(cntl_port) + """)"""

        self.logger.info("""----------------------------------------------
""" + print_header + """
""" + print_body + """""")

        # Increment packet counter
        self.pkts_received += 1