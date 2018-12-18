# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

from ryu.lib.packet import ipv4
from ryu.lib.mac import haddr_to_int
from ryu.lib.packet.arp import ARP_HW_TYPE_ETHERNET, ARP_REPLY
from ryu.lib.packet.ether_types import ETH_TYPE_IP
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, tcp
from ryu.lib.packet.packet import Packet
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet



class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    VIRTUAL_IP = '10.0.0.100'  # The virtual server IP
    VIRTUAL_MAC = "AB:BC:CD:EF:AB:BC"  # Virtual Load Balancer MAC Address

    H1_ip = '10.0.0.1'  # Host 1's IP
    H2_ip = '10.0.0.2'  # Host 2's IP
    H1_mac = '00:00:00:00:00:01'  # Host 1's mac
    H2_mac = '00:00:00:00:00:02'  # Host 2's mac

    ip_to_port = {
        H1_ip: 1,
        H2_ip: 2
    }

    ip_to_mac = {
        '10.0.0.1': '00:00:00:00:00:01',
        '10.0.0.2': '00:00:00:00:00:02',
        '10.0.0.3': '00:00:00:00:00:03',
        '10.0.0.4': '00:00:00:00:00:04',
        '10.0.0.5': '00:00:00:00:00:05',
        '10.0.0.6': '00:00:00:00:00:06'
    }

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        print("switch_features_handler")
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    # Function placed here, source MAC and IP passed from below now become the destination for the reply packet
    def function_for_arp_reply(self, dst_ip, dst_mac):
        print("Entered the ARP Reply function to build a packet and reply back appropriately.")
        arp_target_ip = dst_ip
        arp_target_mac = dst_mac
        src_ip = self.VIRTUAL_IP  # Making the load balancers IP and MAC as source IP and MAC
        src_mac = self.VIRTUAL_MAC

        arp_opcode = 2  # ARP opcode is 2 for ARP reply
        hardware_type = 1  # 1 indicates Ethernet ie 10Mb
        arp_protocol = 2048  # 2048 means IPv4 packet
        ether_protocol = 2054  # 2054 indicates ARP protocol
        len_of_mac = 6  # Indicates length of MAC in bytes
        len_of_ip = 4  # Indicates length of IP in bytes

        pkt = packet.Packet()
        ether_frame = ethernet.ethernet(dst_mac, src_mac, ether_protocol)  # Dealing with only layer 2
        arp_reply_pkt = arp.arp(hardware_type, arp_protocol, len_of_mac, len_of_ip, arp_opcode, src_mac, src_ip,
                                arp_target_mac, dst_ip)  # Building the ARP reply packet, dealing with layer 3
        pkt.add_protocol(ether_frame)
        pkt.add_protocol(arp_reply_pkt)
        pkt.serialize()
        print("Exiting the ARP Reply Function as done with processing for ARP reply packet.")
        return pkt

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        print("*** in _packet_in_handler")
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        print("****** eth.ethertype: " + str(eth.ethertype))
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        # If the packet is an ARP packet, create new flow table
        # entries and send an ARP response.

        print("received packet ")

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            arp_header = pkt.get_protocols(arp.arp)[0]
            dst_ip = arp_header.dst_ip

            if dst_ip == self.VIRTUAL_IP and arp_header.opcode == arp.ARP_REQUEST:
                # Call the function that would build a packet for ARP reply passing source MAC and source IP
                reply_packet = self.function_for_arp_reply(arp_header.src_ip, arp_header.src_mac)
                actions = [parser.OFPActionOutput(in_port)]
                packet_out = parser.OFPPacketOut(datapath=datapath, in_port=ofproto.OFPP_ANY,
                                                 data=reply_packet.data, actions=actions, buffer_id=0xffffffff)
                datapath.send_msg(packet_out)
                print("Debug: Sent the packet_out.")
                return

        if pkt.get_protocols(ipv4.ipv4) and pkt.get_protocols(tcp.tcp):
            ip_header = pkt.get_protocols(ipv4.ipv4)[0]
            print("IP_Header", ip_header)
            tcp_header = pkt.get_protocols(tcp.tcp)[0]
            print("TCP_Header", tcp_header)

            # Route to server
            match = parser.OFPMatch(in_port=in_port, eth_type=eth.ethertype,
                                    ipv4_dst=ip_header.dst)

            if ip_header.src == "10.0.0.3" or ip_header.src == "10.0.0.5":
                server_mac_selected = '00:00:00:00:00:01'
                server_ip_selected = '10.0.0.1'
                server_outport_selected = 1
            else:
                server_mac_selected = '00:00:00:00:00:02'
                server_ip_selected = '10.0.0.2'
                server_outport_selected = 2

            actions = [parser.OFPActionSetField(ipv4_src=self.VIRTUAL_IP),
                       parser.OFPActionSetField(eth_src=self.VIRTUAL_MAC),
                       parser.OFPActionSetField(eth_dst=server_mac_selected),
                       parser.OFPActionSetField(ipv4_dst=server_ip_selected),
                       parser.OFPActionOutput(server_outport_selected)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            flow_mod = parser.OFPFlowMod(datapath=datapath, match=match, priority=0, instructions=inst,
                                         buffer_id=msg.buffer_id)
            print("*** datapath.send_msg(flow_mod): " + str(flow_mod))

            datapath.send_msg(flow_mod)
            print("<========Packet sent from Client :" + str(ip_header.src) + " to Server: " + str(
                server_ip_selected) + ", MAC: " + str(server_mac_selected) + " and on switch port: " + str(
                server_outport_selected) + "========>")

            # Reverse route from server
            match = parser.OFPMatch(in_port=server_outport_selected, eth_type=eth.ethertype,
                                    eth_src=server_mac_selected,
                                    eth_dst=self.VIRTUAL_MAC, ip_proto=ip_header.proto, ipv4_src=server_ip_selected,
                                    ipv4_dst=self.VIRTUAL_IP, tcp_src=tcp_header.dst_port,
                                    tcp_dst=tcp_header.src_port)
            actions = [parser.OFPActionSetField(eth_src=self.VIRTUAL_MAC),
                       parser.OFPActionSetField(ipv4_src=self.VIRTUAL_IP),
                       parser.OFPActionSetField(ipv4_dst=ip_header.src), parser.OFPActionSetField(eth_dst=eth.src),
                       parser.OFPActionOutput(in_port)]
            inst2 = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            flow_mod2 = parser.OFPFlowMod(datapath=datapath, match=match, priority=0, instructions=inst2)

            datapath.send_msg(flow_mod2)
            print("<++++++++Reply sent from server having IP: " + str(server_ip_selected) + ", MAC: " + str(
                server_mac_selected) + " to client:" + str(ip_header.src) + " via load balancer :" + str(
                self.VIRTUAL_IP) + "++++++++>")
        else:

            dst = eth.dst
            src = eth.src  # source MAC address
            dpid = datapath.id
            self.mac_to_port.setdefault(dpid, {})

            self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

            # learn a mac address to avoid FLOOD next time.
            self.mac_to_port[dpid][src] = in_port

            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]

            # install a flow to avoid packet_in next time
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions)
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)


