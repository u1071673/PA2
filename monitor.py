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
#    This is the main monitor file for PA2

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0, ofproto_v1_2, ofproto_v1_3, ofproto_v1_4, ofproto_v1_5
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from array import array


class Monitor(app_manager.RyuApp):
    # OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    # OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION, ofproto_v1_2.OFP_VERSION, ofproto_v1_3.OFP_VERSION, ofproto_v1_4.OFP_VERSION, ofproto_v1_5.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Monitor, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        pkt = packet.Packet(bytearray(msg.data))
        for p in pkt:
            debug_print(p.protocol_name, p)
            if p.protocol_name == 'arp':
                debug_print ('Packet protocol is arp!')
            elif p.protocol_name == 'icmp':
                debug_print('Packet protocol is icmp!')
        # pkt = packet.Packet(msg.data)
        # eth = pkt.get_protocols(ethernet.ethernet)
        #
        #
        # dp = msg.datapath
        # ofp = dp.ofproto
        # ofp_parser = dp.ofproto_parser
        # print(msg)
        # actions = [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD)]
        # out = ofp_parser.OFPPacketOut(
        #     datapath=dp, buffer_id=msg.buffer_id, in_port=msg.in_port,
        #     actions=actions)
        #
        # dp.send_msg(out)
