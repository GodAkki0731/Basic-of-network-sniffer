import unittest
from datetime import datetime
import scapy.all as scapy
from io import StringIO
import sys

def packet_callback(packet):
    # This function should be defined in your module
    print(f"Timestamp: {datetime.now()}")
    print(f"Source IP: {packet.src}, Destination IP: {packet.dst}")

class TestPacketCallback(unittest.TestCase):
    def test_packet_with_ip_layer(self):
        packet = scapy.IP(src='192.168.1.1', dst='8.8.8.8')
        captured_output = StringIO()
        sys.stdout = captured_output
        packet_callback(packet)
        sys.stdout = sys.__stdout__
        self.assertIn('Timestamp:', captured_output.getvalue())
        self.assertIn('Source IP: 192.168.1.1, Destination IP: 8.8.8.8', captured_output.getvalue())

    def test_packet_with_tcp_layer(self):
        packet = scapy.IP(src='192.168.1.1', dst='8.8.8.8') / scapy.TCP(sport=1234, dport=5678)
        captured_output = StringIO()
        sys.stdout = captured_output
        packet_callback(packet)
        sys.stdout = sys.__stdout__
        self.assertIn('Source Port: 1234, Destination Port: 5678', captured_output.getvalue())

    def test_packet_with_udp_layer(self):
        packet = scapy.IP(src='192.168.1.1', dst='8.8.8.8') / scapy.UDP(sport=1234, dport=5678)
        captured_output = StringIO()
        sys.stdout = captured_output
        packet_callback(packet)
        sys.stdout = sys.__stdout__
        self.assertIn('Source Port: 1234, Destination Port: 5678', captured_output.getvalue())

    def test_packet_with_dns_layer_query(self):
        packet = scapy.IP(src='192.168.1.1', dst='8.8.8.8') / scapy.UDP(sport=1234, dport=5678) / scapy.DNS(qd=scapy.DNSRR(rrname='example.com'))
        captured_output = StringIO()
        sys.stdout = captured_output
        packet_callback(packet)
        sys.stdout = sys.__stdout__
        self.assertIn('DNS Query: example.com', captured_output.getvalue())

    def test_packet_with_dns_layer_response(self):
        packet = scapy.IP(src='192.168.1.1', dst='8.8.8.8') / scapy.UDP(sport=1234, dport=5678) / scapy.DNS(an=scapy.DNSRR(rrname='example.com', rdata='1.2.3.4'))
        captured_output = StringIO()
        sys.stdout = captured_output
        packet_callback(packet)
        sys.stdout = sys.__stdout__
        self.assertIn('DNS Response: example.com -> 1.2.3.4', captured_output.getvalue())

    def test_packet_without_ip_layer(self):
        packet = scapy.TCP(sport=1234, dport=5678)
        captured_output = StringIO()
        sys.stdout = captured_output
        packet_callback(packet)
        sys.stdout = sys.__stdout__
        self.assertEqual(captured_output.getvalue(), '')

    def test_packet_with_unknown_protocol(self):
        packet = scapy.IP(src='192.168.1.1', dst='8.8.8.8', proto=255)
        captured_output = StringIO()
        sys.stdout = captured_output
        packet_callback(packet)
        sys.stdout = sys.__stdout__
        self.assertIn('Timestamp:', captured_output.getvalue())
        self.assertIn('Source IP: 192.168.1.1, Destination IP: 8.8.8.8', captured_output.getvalue())

if __name__ == '__main__':
    unittest.main()