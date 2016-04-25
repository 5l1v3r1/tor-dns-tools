#!/usr/bin/env python2
#
# Copyright 2016 Philipp Winter <phw@nymity.ch>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
Turn pcap into csv file.

Extract timestamp, source IP address, and query name of all DNS queries in the
given pcap, and turn it into a CSV.
"""

import sys

import scapy.all as scapy

# We exclude the following two measurement hosts.

MEASUREMENT_HOSTS = frozenset(["92.243.1.186", "198.83.85.34"])


def process_file(pcap_file):

    packets = scapy.rdpcap(pcap_file)
    for packet in packets:

        if not packet.haslayer(scapy.IP):
            continue

        if not packet.haslayer(scapy.DNSQR):
            continue

        query = packet[scapy.DNSQR].qname
        src_addr = packet[scapy.IP].src

        # Skip DNS response.

        if src_addr in MEASUREMENT_HOSTS:
            continue

        print "%s,%s,%s" % (packet.time, packet[scapy.IP].src, query.lower())

    return 0


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print >> sys.stderr, "\nUsage: %s PCAP_FILE\n" % sys.argv[0]
        sys.exit(1)
    pcap_file = sys.argv[1]

    sys.exit(process_file(pcap_file))
