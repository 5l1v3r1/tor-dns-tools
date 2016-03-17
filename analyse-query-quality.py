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
Determine query quality of DNS resolvers in given pcap file.

The code filters DNS queries for `PREFIX.tor.nymity.ch' and determines which
resolvers are poorly configured.
"""

import re
import sys
import time
import logging as log
import datetime

import cymruwhois
import scapy.all as scapy

# IP addresses of machines that were involved in this experiment.

DNS_SERVER_ADDR = "198.83.85.34"
DNS_QUERY_ADDR = "193.11.166.194"

TARGET_DOMAIN = "tor.nymity.ch"

log.basicConfig(level=log.getLevelName("INFO"),
                format="%(asctime)s [%(levelname)s]: %(message)s")

# Maps exit relay fingerprints to DNS queries.

has_lowercase = re.compile("[a-z]")
has_uppercase = re.compile("[A-Z]")
fingerprint_pattern = re.compile("^[a-fA-F0-9]{40,}$")


def has_0x20_encoding(query):
    """
    Return `True' if query uses 0x20 encoding.

    Note that there's a slim chance of false negatives here because a resolver
    could produce an all-lowercase or all-uppercase query despite using 0x20
    encoding.
    """

    return has_lowercase.search(query) and has_uppercase.search(query)


def analyse_queries(exit_queries, whois):
    """
    Iterate over queries and determine their quality.
    """

    has_0x20 = 0
    has_rand_port = 0
    lacks_0x20 = set()
    lacks_rand = set()

    for exit_fpr, info in exit_queries.iteritems():

        query, src_port, src_addr = info

        if has_0x20_encoding(query):
            has_0x20 += 1
        else:
            lacks_0x20.add((exit_fpr, src_addr))

        if src_port != 53:
            has_rand_port += 1
        else:
            lacks_rand.add((exit_fpr, src_addr))

    exit_queries_len = len(exit_queries)
    has_0x20_pct = float(has_0x20) / exit_queries_len * 100
    has_rand_port_pct = float(has_rand_port) / exit_queries_len * 100

    log.info("Extracted queries from %d resolvers." % exit_queries_len)
    log.info("%d out of %d resolvers (%.2f%%) use 0x20 encoding." %
             (has_0x20, exit_queries_len, has_0x20_pct))
    log.info("%d out of %d resolvers (%.2f%%) use random source port." %
             (has_rand_port, exit_queries_len, has_rand_port_pct))

    # Print resolvers that are poorly configured.

    for record, info in zip(whois.lookupmany([addr for _, addr in lacks_0x20]),
                            lacks_0x20):
        exit_fpr, rslv_addr = info
        log.warning("%s %15s (%30s) lacks 0x20." %
                    (exit_fpr[:8], rslv_addr, record.owner[:30]))

    for record, info in zip(whois.lookupmany([addr for _, addr in lacks_rand]),
                            lacks_rand):
        exit_fpr, rslv_addr = info
        log.warning("%s %15s (%30s) lacks random source port." %
                    (exit_fpr[:8], rslv_addr, record.owner[:30]))


def matches_fingerprint(dns_label):
    """
    Return `True' if given dns_label appears to be a fingerprint.
    """

    return fingerprint_pattern.match(dns_label)


def parse_file(pcap_file):
    """
    Parse pcap file and return dictionary mapping exit fingerprint to its info.
    """

    exit_queries = dict()
    try:
        packets = scapy.rdpcap(pcap_file)
    except Exception as err:
        log.critical("Error while reading pcap: %s" % err)
        sys.exit(3)

    for packet in packets:

        if not packet.haslayer(scapy.IP):
            continue
        src_addr = packet[scapy.IP].src

        if src_addr == DNS_QUERY_ADDR or src_addr == DNS_SERVER_ADDR:
            continue

        if not packet.haslayer(scapy.DNSQR):
            continue
        query = packet[scapy.DNSQR].qname

        if TARGET_DOMAIN not in query.lower():
            continue

        # Extract fingerprint and add dictionary entry.

        dns_labels = query.split(".")
        if not matches_fingerprint(dns_labels[0]):
            continue
        exit_fpr = dns_labels[0].lower()
        exit_queries[exit_fpr] = (query, packet[scapy.UDP].sport, src_addr)

    if len(packets) >= 2:
        first, last = packets[0].time, packets[-1].time
        log.info("Trace duration: %s" %
                 str(datetime.timedelta(seconds=last-first)))

    return exit_queries


if __name__ == "__main__":

    if len(sys.argv) != 2:
        log.critical("Usage: %s PCAP_FILE" % sys.argv[0])
        sys.exit(1)
    pcap_file = sys.argv[1]

    before = time.time()
    exit_queries = parse_file(pcap_file)
    log.info("Parsed file in %ss." % str(time.time() - before))

    if len(exit_queries) == 0:
        log.critical("Could not extract any queries from pcap.")
        sys.exit(2)

    analyse_queries(exit_queries, cymruwhois.Client())

    sys.exit(0)
