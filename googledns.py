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
Check if a given IP address is part of Google's set of DNS resolvers.

The netblocks are available online:
    <https://developers.google.com/speed/public-dns/faq?csw=1#locations>
"""


import netaddr

# The following list is from 2016-04-22, and might be subject to modifications.

google_subnets = netaddr.IPSet([
    netaddr.IPNetwork("74.125.16.0/24"),
    netaddr.IPNetwork("74.125.17.0/24"),
    netaddr.IPNetwork("74.125.18.0/24"),
    netaddr.IPNetwork("74.125.19.0/24"),
    netaddr.IPNetwork("74.125.40.0/24"),
    netaddr.IPNetwork("74.125.41.0/24"),
    netaddr.IPNetwork("74.125.42.0/24"),
    netaddr.IPNetwork("74.125.43.0/24"),
    netaddr.IPNetwork("74.125.44.0/24"),
    netaddr.IPNetwork("74.125.45.0/24"),
    netaddr.IPNetwork("74.125.46.0/24"),
    netaddr.IPNetwork("74.125.47.0/24"),
    netaddr.IPNetwork("74.125.72.0/24"),
    netaddr.IPNetwork("74.125.73.0/24"),
    netaddr.IPNetwork("74.125.74.0/24"),
    netaddr.IPNetwork("74.125.75.0/24"),
    netaddr.IPNetwork("74.125.76.0/24"),
    netaddr.IPNetwork("74.125.77.0/24"),
    netaddr.IPNetwork("74.125.78.0/24"),
    netaddr.IPNetwork("74.125.80.0/24"),
    netaddr.IPNetwork("74.125.113.0/24"),
    netaddr.IPNetwork("74.125.114.0/24"),
    netaddr.IPNetwork("74.125.176.0/24"),
    netaddr.IPNetwork("74.125.177.0/24"),
    netaddr.IPNetwork("74.125.178.0/24"),
    netaddr.IPNetwork("74.125.180.0/24"),
    netaddr.IPNetwork("74.125.181.0/24"),
    netaddr.IPNetwork("74.125.182.0/24"),
    netaddr.IPNetwork("74.125.183.0/24"),
    netaddr.IPNetwork("74.125.184.0/24"),
    netaddr.IPNetwork("74.125.185.0/24"),
    netaddr.IPNetwork("74.125.186.0/24"),
    netaddr.IPNetwork("74.125.187.0/24"),
    netaddr.IPNetwork("74.125.190.0/24"),
    netaddr.IPNetwork("173.194.89.0/24"),
    netaddr.IPNetwork("173.194.90.0/24"),
    netaddr.IPNetwork("173.194.91.0/24"),
    netaddr.IPNetwork("173.194.92.0/24"),
    netaddr.IPNetwork("173.194.93.0/24"),
    netaddr.IPNetwork("173.194.95.0/24"),
    netaddr.IPNetwork("173.194.96.0/24"),
    netaddr.IPNetwork("173.194.98.0/24"),
    netaddr.IPNetwork("173.194.99.0/24"),
    netaddr.IPNetwork("2001:4860:400b::/48"),
    netaddr.IPNetwork("2404:6800:4003::/48"),
    netaddr.IPNetwork("2404:6800:4008::/48"),
    netaddr.IPNetwork("2607:f8b0:4001::/48"),
    netaddr.IPNetwork("2607:f8b0:4002::/48"),
    netaddr.IPNetwork("2607:f8b0:4003::/48"),
    netaddr.IPNetwork("2607:f8b0:400c::/48"),
    netaddr.IPNetwork("2607:f8b0:400d::/48"),
    netaddr.IPNetwork("2607:f8b0:400e::/48"),
    netaddr.IPNetwork("2800:3f0:4003::/48"),
    netaddr.IPNetwork("2a00:1450:400b::/48"),
    netaddr.IPNetwork("2a00:1450:400c::/48"),
    netaddr.IPNetwork("2a00:1450:4010::/48"),
    netaddr.IPNetwork("2a00:1450:4013::/48"),
])


def is_google(addr):
    """
    Return `True' iff the given IP address is a Google resolver.
    """

    return netaddr.IPAddress(addr) in google_subnets
