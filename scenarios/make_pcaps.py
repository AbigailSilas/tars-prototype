"""Build the simulated incident scenarios as PCAP files (no live network needed).

Run:  python scenarios/make_pcaps.py
Addresses: 192.168.10.x = facility devices (see config/assets.yaml);
203.0.113.0/24 and 198.51.100.0/24 are documentation ranges (RFC 5737),
so the files can never point at a real outside server.
"""
import os
from scapy.all import DNS, DNSQR, ICMP, IP, TCP, UDP, Raw, wrpcap

OUT = os.path.join(os.path.dirname(__file__), "pcaps")
os.makedirs(OUT, exist_ok=True)


def http_session(server, client, cport, body):
    """A complete TCP conversation in which the server's reply contains `body`."""
    s, c = 1000, 5000
    req = b"GET /uid/index.html HTTP/1.1\r\nHost: test\r\n\r\n"
    resp = b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body)
    return [
        IP(src=client, dst=server) / TCP(sport=cport, dport=80, flags="S", seq=c),
        IP(src=server, dst=client) / TCP(sport=80, dport=cport, flags="SA", seq=s, ack=c + 1),
        IP(src=client, dst=server) / TCP(sport=cport, dport=80, flags="A", seq=c + 1, ack=s + 1),
        IP(src=client, dst=server) / TCP(sport=cport, dport=80, flags="PA", seq=c + 1, ack=s + 1) / Raw(req),
        IP(src=server, dst=client) / TCP(sport=80, dport=cport, flags="PA", seq=s + 1, ack=c + 1 + len(req)) / Raw(resp),
        IP(src=client, dst=server) / TCP(sport=cport, dport=80, flags="A", seq=c + 1 + len(req), ack=s + 1 + len(resp)),
        IP(src=client, dst=server) / TCP(sport=cport, dport=80, flags="FA", seq=c + 1 + len(req), ack=s + 1 + len(resp)),
        IP(src=server, dst=client) / TCP(sport=80, dport=cport, flags="FA", seq=s + 1 + len(resp), ack=c + 2 + len(req)),
        IP(src=client, dst=server) / TCP(sport=cport, dport=80, flags="A", seq=c + 2 + len(req), ack=s + 2 + len(resp)),
    ]


def repeated(server, client, base_port, times):
    return sum((http_session(server, client, base_port + i, ROOT) for i in range(times)), [])


ROOT = b"uid=0(root) gid=0(root) groups=0(root)"

scenarios = {
    # S1: a blocklisted outside server repeatedly answers a workstation with a root id string
    "s1_repeated_attack_workstation": repeated("203.0.113.50", "192.168.10.21", 40000, 4),
    # S2: the same activity aimed at the protected EHR server
    "s2_repeated_attack_ehr_server": repeated("203.0.113.50", "192.168.10.5", 41000, 4),
    # S3: a single event from an address that is not on the blocklist
    "s3_single_event_unknown_source": http_session("198.51.100.77", "192.168.10.22", 42000, ROOT),
    # S4: a workstation looks up a known bad domain
    "s4_bad_domain_lookup": [IP(src="192.168.10.22", dst="192.168.10.1") / UDP(sport=53000, dport=53)
                             / DNS(rd=1, qd=DNSQR(qname="bad-domain.example"))],
    # S5: someone outside pings a workstation
    "s5_external_ping": [IP(src="198.51.100.9", dst="192.168.10.21") / ICMP(type=8)],
    # S6: suspicious traffic between two internal workstations (lateral movement)
    "s6_internal_lateral": repeated("192.168.10.22", "192.168.10.21", 43000, 4),
    # S7: repeated attack from a blocklisted address on the protected lab analyser
    "s7_repeated_attack_medical_device": repeated("203.0.113.50", "192.168.10.30", 44000, 4),
    # S8: repeated attack from an address that is NOT on the blocklist
    "s8_repeated_unknown_source": repeated("198.51.100.77", "192.168.10.21", 45000, 4),
}

for name, packets in scenarios.items():
    path = os.path.join(OUT, name + ".pcap")
    wrpcap(path, packets)
    print("wrote", path)
