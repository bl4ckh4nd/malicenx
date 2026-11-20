#!/usr/bin/env python3
"""Synthetic STARTTLS relay for the outbound report acceptance test."""

from email import policy
from email.parser import BytesParser
from pathlib import Path
import argparse
import socket
import ssl

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("cert", type=Path)
parser.add_argument("key", type=Path)
parser.add_argument("report", type=Path)
parser.add_argument("--port", type=int, default=42527)
args = parser.parse_args()

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(args.cert, args.key)

with socket.create_server(("127.0.0.1", args.port)) as listener:
    listener.settimeout(60)
    for attempt in range(2):
        connection, _ = listener.accept()
        connection.settimeout(15)
        with connection.makefile("rb") as reader:
            connection.sendall(b"220 localhost ESMTP test relay\r\n")
            assert reader.readline().startswith(b"EHLO ")
            connection.sendall(b"250-localhost\r\n250 STARTTLS\r\n")
            assert reader.readline() == b"STARTTLS\r\n"
            connection.sendall(b"220 Ready for TLS\r\n")
        # The socket must remain open during its upgrade.
        with context.wrap_socket(connection, server_side=True) as tls, tls.makefile("rb") as reader:
            assert reader.readline().startswith(b"EHLO ")
            tls.sendall(b"250 localhost\r\n")
            assert reader.readline().upper().startswith(b"MAIL FROM:<SCANNER@EXAMPLE.TEST>")
            tls.sendall(b"250 Sender accepted\r\n")
            assert reader.readline().upper().startswith(b"RCPT TO:<REPORTS@EXAMPLE.TEST>")
            tls.sendall(b"250 Recipient accepted\r\n")
            assert reader.readline() == b"DATA\r\n"
            tls.sendall(b"354 Send message\r\n")
            data = bytearray()
            while line := reader.readline():
                if line == b".\r\n":
                    break
                data.extend(line)
            else:
                raise RuntimeError("unterminated SMTP data")
            if attempt == 0:
                tls.sendall(b"451 Try again later\r\n")
                continue

            report = BytesParser(policy=policy.default).parsebytes(data)
            body = report.get_content()
            assert report["To"] == "reports@example.test" and report["From"] == "scanner@example.test"
            assert "Report: http://127.0.0.1:43993/scans/" in body
            assert "Synthetic mail" not in body
            args.report.write_bytes(data)
            tls.sendall(b"250 Report stored\r\n")
            if reader.readline() == b"QUIT\r\n":
                tls.sendall(b"221 Bye\r\n")
