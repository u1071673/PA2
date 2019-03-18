from ryu.base import app_manager
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet


class L2Forwarding(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(L2Forwarding, self).__init__(*args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg  # Object representing a packet_in data structure.
        datapath = msg.datapath  # Switch Datapath ID
        ofproto = datapath.ofproto  # OpenFlow Protocol version the entities negotiated. In our case OF1.3

        # We can inspect the packet headers for several packet types: ARP, Ethernet, ICMP, IPv4, IPv6, MPLS, OSPF, LLDP,
        # TCP, UDP. For set of packet types supported refer to this link
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # I use the following two useful commands to extract Ether header details:
        # dst = eth.dst
        # src = eth.src

        # Similarly, the OFPPacketOut class can be used to build a packet_out message with the required information
        # (e.g., Datapath ID, associated actions etc)
        out = ofp_parser.OFPPacketOut(datapath=dp, in_port=msg.in_port, actions=actions)  # Generate the message
        dp.send_msg(out)  # Send the message to the switch

        # Besides a PACKET_OUT, we can also perform a FLOW_MOD insertion into a switch. For this, we build the Match,
        # Action, Instructions and generate the required Flow. Here is an example of how to create a match header where
        # the in_port and eth_dst matches are extracted from the PACKET_IN:
        msg = ev.msg
        in_port = msg.match['in_port']

        # Get the destination ethernet address
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        dst = eth.dst
        match = parser.OFPMatch(in_port=in_port, eth_dst=dst)

        # There are several other fields you can match, which are defined in line 1130. The supported set of actions is
        # defined in line 230 and the instructions are defined in line 195. Here is an example of creating an action
        # list for the flow.
        actions = [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD)]  # Build the required action

        # OpenFlow 1.3 associates set of instructions with each flow entry such as handling actions to modify/forward
        # packets, support pipeline processing instructions in the case of multi-table, metering instructions to
        # rate-limit traffic etc. The previous set of actions defined in OpenFlow 1.0 are one type of instructions
        # defined in OpenFlow 1.3.
        # Once the match rule and action list is formed, instructions are created as follows:
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        # Given the above code, a Flow can be generated and added to a particular switch.
        mod = parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=inst)
        datapath.send_msg(mod)
