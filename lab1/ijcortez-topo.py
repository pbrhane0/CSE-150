#! /usr/bin/python3

# ijcortez-topo.py
#
# Ismael Cortez
# 1/14/2021
# CSE 150 Lab 1
#
# This script creates a custom topology
#

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI

class MyTopology(Topo):
	"""
		A basic topology.
	"""

	def __init__(self):
		Topo.__init__(self)

		# Set up topology here
		# Begin by adding all of the hosts (1 - 5)
		# host_name = addHost(self, name, opts)
		host1 = self.addHost("h1") # Adds host1
		host2 = self.addHost("h2")
		host3 = self.addHost("h3")
		host4 = self.addHost("h4")
		host5 = self.addHost("h5")

		# Next add all of the switches (1 - 3)
		# switch_name = addSwitch(self, name, opts)
		switch1 = self.addSwitch("s1") # Adds switch1
		switch2 = self.addSwitch("s2")
		switch3 = self.addSwitch("s3")

		# Add all of the links (1 - 7)
		# link_info_key = addLink(self, node1, node2, port1 = None, port2 = None, key = None, opts)
		self.addLink(host1, switch1) # Adds a link
		self.addLink(host2, switch1)
		self.addLink(host3, switch2)
		self.addLink(host4, switch2)
		self.addLink(switch1, switch3)
		self.addLink(switch2, switch3)
		self.addLink(switch3, host5)

if __name__ == "__main__":
	"""
	If this script is run as an executable (by chmod +x), this is what it will do
	"""

	topo = MyTopology() # Creates the topology
	net = Mininet( topo=topo ) # Loads the topology
	net.start()

	# Commands here will run on the simulated topology
	CLI(net)

	net.stop() # Stops Mininet

