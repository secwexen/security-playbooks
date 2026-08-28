from __future__ import annotations

from pathlib import Path

from scapy.all import DNS, DNSQR, IP, Raw, TCP, UDP, wrpcap


BASE = Path(__file__).resolve().parent / "fixtures"


def create_c2_http() -> None:
    packets = [
        IP(src="10.10.10.10", dst="192.168.1.10")
        / TCP(
            sport=4444,
            dport=80,
            flags="PA",
        )
        / Raw(
            load=(
                b"GET /beacon HTTP/1.1\r\n"
                b"Host: malicious.example\r\n"
                b"User-Agent: evil-client\r\n"
                b"\r\n"
            )
        )
    ]

    wrpcap(
        str(BASE / "c2_http.pcap"),
        packets,
    )


def create_dns_tunnel() -> None:
    packets = [
        IP(
            src="10.10.10.20",
            dst="8.8.8.8",
        )
        / UDP(
            sport=53000,
            dport=53,
        )
        / DNS(
            rd=1,
            qd=DNSQR(
                qname=(
                    "dGVzdC10dW5uZWwtcGF5bG9hZA=="
                    ".malicious.example"
                )
            ),
        )
    ]

    wrpcap(
        str(BASE / "dns_tunnel.pcap"),
        packets,
    )


def create_sample_traffic() -> None:
    packets = [
        IP(
            src="192.168.1.100",
            dst="192.168.1.1",
        )
        / TCP(
            sport=12345,
            dport=80,
            flags="S",
        ),
        IP(
            src="192.168.1.1",
            dst="192.168.1.100",
        )
        / TCP(
            sport=80,
            dport=12345,
            flags="SA",
        ),
    ]

    wrpcap(
        str(BASE / "sample_traffic.pcap"),
        packets,
    )


def main() -> None:
    BASE.mkdir(
        parents=True,
        exist_ok=True,
    )

    create_c2_http()
    create_dns_tunnel()
    create_sample_traffic()

    print(
        "Suricata PCAP fixtures generated successfully."
    )


if __name__ == "__main__":
    main()
