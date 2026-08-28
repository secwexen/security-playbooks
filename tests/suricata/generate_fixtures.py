from __future__ import annotations

from pathlib import Path

from scapy.all import (
    DNS,
    DNSQR,
    DNSRROPT,
    Ether,
    IP,
    Raw,
    TCP,
    UDP,
    wrpcap,
)


BASE = Path(__file__).resolve().parent / "fixtures"


def create_c2_http() -> None:
    """
    Create a TCP handshake followed by an HTTP request
    containing User-Agent: curl.
    """

    client_ip = "10.10.10.10"
    server_ip = "192.168.1.10"
    client_port = 4444
    server_port = 80

    packets = [
        # TCP SYN
        IP(
            src=client_ip,
            dst=server_ip,
        )
        / TCP(
            sport=client_port,
            dport=server_port,
            flags="S",
            seq=1000,
        ),

        # TCP SYN/ACK
        IP(
            src=server_ip,
            dst=client_ip,
        )
        / TCP(
            sport=server_port,
            dport=client_port,
            flags="SA",
            seq=2000,
            ack=1001,
        ),

        # TCP ACK
        IP(
            src=client_ip,
            dst=server_ip,
        )
        / TCP(
            sport=client_port,
            dport=server_port,
            flags="A",
            seq=1001,
            ack=2001,
        ),

        # HTTP request
        IP(
            src=client_ip,
            dst=server_ip,
        )
        / TCP(
            sport=client_port,
            dport=server_port,
            flags="PA",
            seq=1001,
            ack=2001,
        )
        / Raw(
            load=(
                b"GET /beacon HTTP/1.1\r\n"
                b"Host: malicious.example\r\n"
                b"User-Agent: curl/8.0\r\n"
                b"Accept: */*\r\n"
                b"Connection: close\r\n"
                b"\r\n"
            )
        ),
    ]

    output = BASE / "c2_http.pcap"

    wrpcap(
        str(output),
        packets,
    )


def create_dns_tunnel() -> None:
    """
    Create a DNS TXT query containing example.test.
    """

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
                qname="example.test",
                qtype="TXT",
            ),
        )
    ]

    output = BASE / "dns_tunnel.pcap"

    wrpcap(
        str(output),
        packets,
    )


def create_sample_traffic() -> None:
    """
    Create ordinary TCP traffic that should not trigger
    the repository detection rules.
    """

    client_ip = "192.168.1.100"
    server_ip = "192.168.1.1"

    packets = [
        IP(
            src=client_ip,
            dst=server_ip,
        )
        / TCP(
            sport=12345,
            dport=443,
            flags="S",
            seq=1000,
        ),

        IP(
            src=server_ip,
            dst=client_ip,
        )
        / TCP(
            sport=443,
            dport=12345,
            flags="SA",
            seq=2000,
            ack=1001,
        ),

        IP(
            src=client_ip,
            dst=server_ip,
        )
        / TCP(
            sport=12345,
            dport=443,
            flags="A",
            seq=1001,
            ack=2001,
        ),
    ]

    output = BASE / "sample_traffic.pcap"

    wrpcap(
        str(output),
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
        "PCAP fixtures generated successfully."
    )

    for path in sorted(
        BASE.glob("*.pcap")
    ):
        print(
            f"{path.name}: "
            f"{path.stat().st_size} bytes"
        )


if __name__ == "__main__":
    main()
