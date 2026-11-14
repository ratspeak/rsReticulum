#!/usr/bin/env python3
"""Upstream Transport defaults from upstream RNS 1.6.0 code with no Reticulum instance: the
default receipt timeout (Packet.py:427-433) and next_hop_interface_hw_mtu for UDP and TCP next
hops (Transport.py:3516-3523).
Usage: generate.py [OUT_DIR]
"""
import json, os, time
from _common import RNS, provenance, out_path
from RNS.Interfaces.UDPInterface import UDPInterface
from RNS.Interfaces.TCPInterface import TCPClientInterface
T = RNS.Transport
RNS.loglevel = RNS.LOG_CRITICAL
class Owner: is_connected_to_shared_instance = False
T.owner = Owner(); T.identity = RNS.Identity()

def stub(cls, bitrate, hw_mtu):
    i = object.__new__(cls); i.name = cls.__name__; i.bitrate = bitrate; i.HW_MTU = hw_mtu
    return i
def install_path(dest, iface, hops):
    now = time.time()
    T.path_table[dest] = [now, os.urandom(16), hops, now + 3600, [], iface, os.urandom(32), now]

udp_dest, tcp_dest = bytes([0x21]) * 16, bytes([0x22]) * 16
install_path(udp_dest, stub(UDPInterface, 10_000_000, 1064), 1)
install_path(tcp_dest, stub(TCPClientInterface, 10_000_000, 262144), 1)
hw_mtu = {"udp": {"hw_mtu": 1064, "result": T.next_hop_interface_hw_mtu(udp_dest)},
          "tcp": {"hw_mtu": 262144, "result": T.next_hop_interface_hw_mtu(tcp_dest)}}

class FakeReticulum:
    is_connected_to_shared_instance = False
    def get_first_hop_timeout(self, h): return T.first_hop_timeout(h)
RNS.Reticulum.get_instance = staticmethod(lambda: FakeReticulum())
def receipt_timeout(dest_hash):
    od = RNS.Destination(RNS.Identity(), RNS.Destination.OUT, RNS.Destination.SINGLE, "tad", "receipt")
    od.hash = dest_hash
    p = RNS.Packet(od, b"x"); p.pack()
    return RNS.PacketReceipt(p).timeout
receipt_dest = bytes([0x47]) * 16
install_path(receipt_dest, stub(TCPClientInterface, 10_000_000, 262144), 1)
receipt = {"bitrate": 10_000_000, "hops": 1, "timeout": receipt_timeout(receipt_dest),
           "no_path_timeout": receipt_timeout(bytes([0x48]) * 16)}

out = {"provenance": provenance(__file__), "next_hop_hw_mtu": hw_mtu, "receipt": receipt}
with open(out_path("transport_api_defaults.json"), "w") as f:
    f.write("{\n" + ",\n".join(f" {json.dumps(k)}: {json.dumps(v)}" for k, v in out.items()) + "\n}\n")
os._exit(0)
