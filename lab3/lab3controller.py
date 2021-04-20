# lab3controller.py
#
# Ismael Cortez (ijcortez)
# 2/11/2021
# CSE 150 Lab 3
#
# Based on of_tutorial by James McCauley
#
# The following sources provided example code and/or logic that was used in this file:
# https://github.com/CPqD/RouteFlow/blob/master/pox/pox/forwarding/l2_learning.py
# https://stackoverflow.com/questions/37140542/how-to-check-packet-type-is-tcy-syn-or-rst-in-pox-controller
# http://csie.nqu.edu.tw/smallko/sdn/measure_traffic.pdf
#

from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

class Firewall (object):
  """
  A Firewall object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

  def do_firewall (self, packet, packet_in):
    # The code in here will be executed for every packet.
    # Find any packets with the given protocols
    arp_found = packet.find("arp")
    ipv4_found = packet.find("ipv4")
    tcp_found = packet.find("tcp")

    if arp_found is not None:
      self.accept(packet, packet_in)

    elif ipv4_found is not None:
      icmp_found = packet.find("icmp")
      if icmp_found is not None:
      	self.accept(packet, packet_in)
      elif (tcp_found is not None) and ((ipv4_found.srcip == "10.0.1.10" and ipv4_found.dstip == "10.0.1.20") or (ipv4_found.srcip == "10.0.1.20" and ipv4_found.dstip == "10.0.1.10")):
      	self.accept(packet, packet_in)
      else:
        self.drop(packet, packet_in)
    
    else:
    	self.drop(packet, packet_in)
    
  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.
    self.do_firewall(packet, packet_in)

  def accept (self, packet, packet_in):
    """
    If the packet has been identified as containing any given protocol
    we process and acccept the packet here.
    """
    msg = of.ofp_flow_mod() # define an openflow entry
    msg.match = of.ofp_match.from_packet(packet) # match incoming packet
    msg.idle_timeout = 50 # delete if packet is not matched
    msg.hard_timeout = 50 # delete packet on hard timeout
    msg.buffer_id = packet_in.buffer_id # tell the host where to buffer packet
    msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD)) # define the flood action
    msg.data = packet_in # set the msg data
    self.connection.send(msg) # send out the message

  def drop (self, packet, packet_in):
    """
    If the packet has not been identified as containing any given protocol
    we process and drop the packet here.
    """
    msg = of.ofp_flow_mod() # define an openflow entry
    msg.match = of.ofp_match.from_packet(packet) # match incoming packet
    msg.idle_timeout = 50 # delete if packet is not matched
    msg.hard_timeout = 50 # delete packet on hard timeout
    msg.buffer_id = packet_in.buffer_id # tell the host where to buffer packet
    self.connection.send(msg) # send out the message

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Firewall(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)

