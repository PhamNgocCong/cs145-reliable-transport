
import argparse
import socket
import sys
import time

from utils import PacketHeader, compute_checksum


HEADER_SIZE = 16
MAX_PAYLOAD_SIZE = 1456

START = 0
END = 1
DATA = 2
ACK = 3

TIMEOUT = 0.5


def make_packet(packet_type, seq_num, payload=b""):
    """Create a packet with a CRC32 checksum."""
    header = PacketHeader(
        type=packet_type,
        seq_num=seq_num,
        length=len(payload),
        checksum=0,
    )

    packet = header / payload
    header.checksum = compute_checksum(packet)

    return bytes(header / payload)


def parse_ack(packet):
    """Return the ACK sequence number, or None if invalid."""
    if len(packet) != HEADER_SIZE:
        return None

    header = PacketHeader(packet[:HEADER_SIZE])

    if header.type != ACK or header.length != 0:
        return None

    received_checksum = header.checksum
    header.checksum = 0

    if received_checksum != compute_checksum(header):
        return None

    return header.seq_num


def sender(receiver_ip, receiver_port, window_size):
    if window_size <= 0:
        raise ValueError("window_size must be greater than zero")

    # Read the complete message from standard input.
    message = sys.stdin.buffer.read()

    # Split the message into DATA payloads.
    chunks = [
        message[i:i + MAX_PAYLOAD_SIZE]
        for i in range(0, len(message), MAX_PAYLOAD_SIZE)
    ]

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)
    destination = (receiver_ip, receiver_port)

    def send_and_wait(packet, expected_ack):
        """Retransmit until the expected ACK is received."""
        while True:
            sock.sendto(packet, destination)
            deadline = time.monotonic() + TIMEOUT

            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break

                sock.settimeout(remaining)

                try:
                    response, address = sock.recvfrom(2048)
                except socket.timeout:
                    break

              

                ack_num = parse_ack(response)
                if ack_num == expected_ack:
                    return

    try:
        # Establish the connection.
        send_and_wait(make_packet(START, 0), 1)

        # DATA sequence numbers start at 1.
        packets = {
            i + 1: make_packet(DATA, i + 1, chunk)
            for i, chunk in enumerate(chunks)
        }

        base = 1
        next_seq = 1
        total = len(chunks)

        # Sliding-window transmission with cumulative ACKs.
        while base <= total:
            while next_seq <= total and next_seq < base + window_size:
                sock.sendto(packets[next_seq], destination)
                next_seq += 1

            sock.settimeout(TIMEOUT)

            try:
                response, address = sock.recvfrom(2048)
            except socket.timeout:
                # Retransmit all outstanding packets after a timeout.
                for seq in range(base, next_seq):
                    sock.sendto(packets[seq], destination)
                continue

          

            ack_num = parse_ack(response)

            if ack_num is not None and base < ack_num <= next_seq:
                base = ack_num

        # END uses the next sequence number after the DATA packets.
        end_seq = total + 1
        send_and_wait(make_packet(END, end_seq), end_seq + 1)

    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "receiver_ip",
        help="The IP address of the host that receiver is running on",
    )
    parser.add_argument(
        "receiver_port",
        type=int,
        help="The port number on which receiver is listening",
    )
    parser.add_argument(
        "window_size",
        type=int,
        help="Maximum number of outstanding packets",
    )

    args = parser.parse_args()
    sender(args.receiver_ip, args.receiver_port, args.window_size)


if __name__ == "__main__":
    main()
