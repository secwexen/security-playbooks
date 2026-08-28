from pathlib import Path

from scapy.all import DNS, DNSQR, Ether, ICMP, IP, Raw, TCP, UDP, wrpcap


BASE = Path(__file__).parent / "fixtures"


def create_c2_http() -> None:
    packets = [
        Ether()
        / IP(src="10.0.0.10", dst="93.184.216.34")
        / TCP(sport=49152, dport=80, flags="S", seq=1000),
        Ether()
        / IP(src="93.184.216.34", dst="10.0.0.10")
        / TCP(sport=80, dport=49152, flags="SA", seq=2000, ack=1001),
        Ether()
        / IP(src="10.0.0.10", dst="93.184.216.34")
        / TCP(sport=49152, dport=80, flags="A", seq=1001, ack=2001),
        Ether()
        / IP(src="10.0.0.10", dst="93.184.216.34")
        / TCP(sport=49152, dport=80, flags="PA", seq=1001, ack=2001)
        / Raw(
            b"GET /beacon HTTP/1.1\r\n"
            b"Host: example.test\r\n"
            b"User-Agent: curl\r\n"
            b"Connection: close\r\n\r\n"
        ),
    ]

    wrpcap(BASE / "c2_http.pcap", packets)


def create_dns_tunnel() -> None:
    packet = (
        Ether()
        / IP(src="10.0.0.20", dst="8.8.8.8")
        / UDP(sport=53000, dport=53)
        / DNS(
            rd=1,
            qd=DNSQR(
                qname="tunnel.example.test",
                qtype="TXT",
            ),
        )
    )

    wrpcap(BASE / "dns_tunnel.pcap", [packet])


def create_sample_traffic() -> None:
    packet = (
        Ether()
        / IP(src="10.0.0.30", dst="192.168.1.1")
        / ICMP()
    )

    wrpcap(BASE / "sample_traffic.pcap", [packet])


def main() -> None:
    BASE.mkdir(parents=True, exist_ok=True)

    create_c2_http()
    create_dns_tunnel()
    create_sample_traffic()

    print("3 Suricata PCAP fixtures created.")


if __name__ == "__main__":
    main()
