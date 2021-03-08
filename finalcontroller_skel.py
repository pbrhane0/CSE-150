# finalcontroller_skel.py
#
# Ismael Cortez
# 3/1/2021
# CSE 150/L Final Project
#
# This script implements the Pox Controller for the company network.
#
# The following sources provided example code and/or logic that was used in this file:
# https://github.com/CPqD/RouteFlow/blob/master/pox/pox/forwarding/l2_learning.py
# https://stackoverflow.com/questins/37140542/how-to-check-packet-type-is-tcp-syn-or-rst-in-pox-controller
# http://csie.nqu.edu.tw/smallko/sdn/measure_traffic.pdf
#
# Hints/Reminders from Lab 3:
#
# To check the source and destination of an IP packet, you can use
# the header information... For example:
#
# ip_header = packet.find('ipv4')
#
# if ip_header.srcip == "1.1.1.1":
#   print "Packet is from 1.1.1.1"
#
# Important Note: the "is" comparison DOES NOT work for IP address
# comparisons in this way. You must use ==.
# 
# To send an OpenFlow Message telling a switch to send packets out a
# port, do the following, replacing <PORT> with the port number the 
# switch should send the packets out:
#
#    msg = of.ofp_flow_mod()
#    msg.match = of.ofp_match.from_packet(packet)
#    msg.idle_timeout = 30
#    msg.hard_timeout = 30
#
#    msg.actions.append(of.ofp_action_output(port = <PORT>))
#    msg.data = packet_in
#    self.connection.send(msg)
#
# To drop packets, simply omit the action.
#

from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

class Final (object):
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

  def do_final (self, packet, packet_in, port_on_switch, switch_id):
    # This is where you'll put your code. The following modifications have 
    # been made from Lab 3:
    #   - port_on_switch: represents the port that the packet was received on.
    #   - switch_id represents the id of the switch that received the packet.
    #      (for example, s1 would have switch_id == 1, s2 would have switch_id == 2, etc...)
    # You should use these to determine where a packet came from. To figure out where a packet 
    # is going, you can use the IP header information.
    
    # find any packets with the given protocols
    find_icmp = packet.find("icmp")
    find_ipv4 = packet.find("ipv4")

    if(find_ipv4 is not None):
    	if(switch_id == 1):
    		#######################################################################
    		# Switch 1 (s1) AKA Floor 1 Switch 1
    		#
    		# Connected Hosts: h10 and h20
    		#######################################################################
    		if(port_on_switch == 8):
    			# Source is Host 10 send to Port 9 or Port 3
    			if(find_ipv4.dstip == "10.1.2.20"):
    				self.accept(packet, packet_in, 9)
    			else:
    				self.accept(packet, packet_in, 3)
    		elif(port_on_switch == 9):
    			# Source is Host 20 send to Port 8 or Port 3
    			if(find_ipv4.dstip == "10.1.1.10"):
    				self.accept(packet, packet_in, 8)
    			else:
    				self.accept(packet, packet_in, 3)
    		elif(port_on_switch == 3):
    			# Source is port 3 send to Port 8 or Port 9
    			if(find_ipv4.dstip == "10.1.1.10"):
    				self.accept(packet, packet_in, 8)
    			elif(find_ipv4.dstip == "10.1.2.20"):
    				self.accept(packet, packet_in, 9)
    			else:
    				# Drop packet if coming from unknown port
    				self.drop(packet, packet_in)
    		else:
    			# Drop packet if coming from unknown port
    			self.drop(packet, packet_in)
    	elif(switch_id == 2):
    		#######################################################################
    		# Switch 2 (s2) AKA Floor 1 Switch 2
    		#
    		# Connected Hosts: h30 and h40
    		#######################################################################
    		if(port_on_switch == 8):
    			# Source is Host 30 send to Port 9 or Port 3
    			if(find_ipv4.dstip == "10.1.4.40"):
    				self.accept(packet, packet_in, 9)
    			else:
    				self.accept(packet, packet_in, 3)
    		elif(port_on_switch == 9):
    			# Source is Host 50 send to Port 8 or Port 3
    			if(find_ipv4.dstip == "10.1.3.30"):
    				self.accept(packet, packet_in, 8)
    			else:
    				self.accept(packet, packet_in, 3)
    		elif(port_on_switch == 3):
    			# Source is Port 3 send to Port 8 or Port 9
    			if(find_ipv4.dstip == "10.1.3.30"):
    				self.accept(packet, packet_in, 8)
    			elif(find_ipv4.dstip == "10.1.4.40"):
    				self.accept(packet, packet_in, 9)
    			else:
    				# Drop packet if not addressed to known Host
    				self.drop(packet, packet_in)
    		else:
    			# Drop packet coming from unknown port
    			self.drop(packet, packet_in)
    	elif(switch_id == 3):
    		###################################################################
    		# Switch 3 (s3) AKA Floor 2 Switch 1
    		#
    		# Connected Hosts: h50 and h60
    		###################################################################
    else:
    	# Flood all non-IP traffic
    	self.accept(packet, packet_in, of.OFPP_FLOOD)

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """
    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return
    packet_in = event.ofp # The actual ofp_packet_in message.
    self.do_final(packet, packet_in, event.port, event.dpid)

  def accept(self, packet, packet_in, output_port):
  	"""
  	If the packet has been identified as containing any given protocol
  	we process and accept the packet here
  	"""
  	msg = of.ofp_flow_mod() # Define an openflow entry
  	msg.match = of.ofp_match.from_packet(packet) # Match incoming packet
  	msg.idle_timeout = 30 # Delete if packet is not matched
  	msg.hard_timeout = 30 # Delete packet on hard timeout
  	msg.buffer_id = packet_in.buffer_id # Tell the host where to buffer packet
  	msg.actions.append(of.ofp_action_output(port = output_port)) # Define the port action
  	msg.data = packet_in # Set the message data
  	self.connection.send(msg)

  def drop(self, packet, packet_in):
  	"""
  	If the packet has not been identified as containing any given protocol
  	we process and drop the packet here
  	"""
  	msg = of.ofp_flow_mod() # Define an openflow entry
  	msg.match = of.ofp_match.from_packet(packet) # Match incoming packet
  	msg.idle_timeout = 30 # Delete if packet is not matched
  	msg.hard_timeout = 30 # Delete packet on hard timeout
  	msg.buffer_id = packet_in.buffer_id # Tell the host where to buffer packet
  	self.connection.send(msg)

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Final(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
