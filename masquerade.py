#!/usr/bin/python2

# NAT MASQUERADE emulator
# Copyright (C) 2015 Bartlomiej Puget <larhard@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

import argparse

from scapy.all import *


class Translator:
	def __init__(self, src_iface, dst_iface):
		self.src_iface = src_iface
		self.src_iface_ip = get_if_addr(self.src_iface)
		self.src_iface_mac = get_if_hwaddr(self.src_iface)

		self.dst_iface = dst_iface
		self.dst_iface_ip = get_if_addr(self.dst_iface)
		self.dst_iface_mac = get_if_hwaddr(self.dst_iface)

		self.connection = {}

	def __call__(self, packet):
		if conf.verb == 1: print packet.summary()
		if conf.verb >= 2: print packet.show2()

		if IP in packet[0]:
			src_mac = packet[0].fields['src']
			src_ip = packet[1].fields['src']
			src_port = packet[2].fields.get('sport')

			dst_mac = packet[0].fields['dst']
			dst_ip = packet[1].fields['dst']
			dst_port = packet[2].fields.get('dport')

			if dst_mac == self.src_iface_mac and src_ip != self.dst_iface_ip and \
					dst_ip != self.src_iface_ip and dst_ip != self.dst_iface_ip:

				altered = packet.copy()
				del(altered[0].src)
				del(altered[0].dst)
				del(altered[1].chksum)

				self.connection[(dst_ip, dst_port, src_port)] = src_ip

				altered[1].fields['src'] = self.dst_iface_ip

				sendp(altered, iface=self.dst_iface)
				if conf.verb == 1: print "-->", altered.summary()
				if conf.verb >= 2: print altered.show2()

			if dst_mac == self.dst_iface_mac and dst_ip == self.dst_iface_ip:
				altered = packet.copy()
				del(altered[0].src)
				del(altered[0].dst)
				del(altered[1].chksum)

				new_dst_ip = self.connection.get((src_ip, src_port, dst_port))

				if new_dst_ip is not None:
					altered[1].fields['dst'] = new_dst_ip

					sendp(altered, iface=self.src_iface)
					if conf.verb == 1: print "-->", altered.summary()
					if conf.verb >= 2: print altered.show2()

			if conf.verb >= 2: print """
----------------------------------------------------------------
"""


def main(src_iface, dst_iface, *args, **kwargs):
	sniff(prn=Translator(src_iface=src_iface, dst_iface=dst_iface))


if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('-s', '--src-iface', help='source interface', required=True)
	parser.add_argument('-d', '--dst-iface', help='destination interface', required=True)
	parser.add_argument('-v', '--verbose', help='make me talk', action='count')

	args = parser.parse_args()

	conf.verb = args.verbose

	main(**vars(args))
