
import argparse
import socket
import sys

from utils import PacketHeader, compute_checksum


HEADER_SIZE = 16
MAX_PACKET_SIZE = 1472
START = 0
END = 1
DATA = 2
ACK = 3


def make_packet(packet_type, seq_num, payload=b""):
    """Create a packet and calculate its checksum."""
    header = PacketHeader(
        type=packet_type,
        seq_num=seq_num,
        length=len(payload),
        checksum=0,
    )

    packet = header / payload
    header.checksum = compute_checksum(packet)

    return bytes(header / payload)


def parse_packet(packet):
    """Parse a packet and validate its checksum."""
    if len(packet) < HEADER_SIZE or len(packet) > MAX_PACKET_SIZE:
        return None

    header = PacketHeader(packet[:HEADER_SIZE])

    if len(packet) != HEADER_SIZE + header.length:
        return None

    payload = packet[HEADER_SIZE:]

    received_checksum = header.checksum
    header.checksum = 0

    calculated_checksum = compute_checksum(header / payload)

    if received_checksum != calculated_checksum:
        return None

    return header, payload


def receiver(receiver_ip, receiver_port, window_size):
    """Receive a reliable message over UDP and print it in order."""
    if window_size <= 0:
        raise ValueError("window_size must be greater than zero")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((receiver_ip, receiver_port))

    active = False
    sender_address = None
    expected_seq = 1
    buffer = {}
    message = bytearray()

    try:
        while True:
            packet, address = sock.recvfrom(2048)

            parsed = parse_packet(packet)

            # Ignore malformed packets and packets with invalid checksums.
            if parsed is None:
                continue

            header, payload = parsed
            packet_type = header.type
            seq_num = header.seq_num

            # A new connection starts with a START packet.
            if packet_type == START:
                if active:
                    continue

                if seq_num != 0 or header.length != 0:
                    continue

                active = True
                sender_address = address
                expected_seq = 1
                buffer.clear()
                message.clear()

                ack = make_packet(ACK, expected_seq)
                sock.sendto(ack, sender_address)
                continue

            # Only accept packets from the active sender.
            if not active or address != sender_address:
                continue

            if packet_type == DATA:
                # Ignore packets outside the receiver's window.
                if seq_num >= expected_seq + window_size:
                    ack = make_packet(ACK, expected_seq)
                    sock.sendto(ack, sender_address)
                    continue

                # Buffer data that has not yet been received.
                if seq_num >= expected_seq:
                    if seq_num not in buffer:
                        buffer[seq_num] = payload

                    # Release consecutive packets in sequence order.
                    while expected_seq in buffer:
                        message.extend(buffer.pop(expected_seq))
                        expected_seq += 1

                # Cumulative ACK: next sequence number expected.
                ack = make_packet(ACK, expected_seq)
                sock.sendto(ack, sender_address)

            elif packet_type == END:
                # END is accepted only after all preceding DATA packets.
                if seq_num == expected_seq and header.length == 0:
                    ack = make_packet(ACK, seq_num + 1)
                    sock.sendto(ack, sender_address)

                    # Write raw bytes rather than Python's bytes representation.
                    sys.stdout.buffer.write(message)
                    sys.stdout.buffer.flush()
                    return

                # Earlier packets may still be missing.
                ack = make_packet(ACK, expected_seq)
                sock.sendto(ack, sender_address)

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

    receiver(args.receiver_ip, args.receiver_port, args.window_size)


if __name__ == "__main__":
    main()
