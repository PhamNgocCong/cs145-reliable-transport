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
    if len(packet) < HEADER_SIZE or len(packet) > MAX_PACKET_SIZE:
        return None

    header = PacketHeader(packet[:HEADER_SIZE])

    if len(packet) != HEADER_SIZE + header.length:
        return None

    payload = packet[HEADER_SIZE:]
    received_checksum = header.checksum
    header.checksum = 0

    if received_checksum != compute_checksum(header / payload):
        return None

    return header, payload


def receiver(receiver_ip, receiver_port, window_size):
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

            if parsed is None:
                continue

            header, payload = parsed
            packet_type = header.type
            seq_num = header.seq_num

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

                sock.sendto(make_packet(ACK, 1), sender_address)
                continue

            if not active or address != sender_address:
                continue

            if packet_type == DATA:
                if seq_num >= expected_seq + window_size:
                    continue

                if seq_num >= expected_seq:
                    if seq_num not in buffer:
                        buffer[seq_num] = payload

                    while expected_seq in buffer:
                        message.extend(buffer.pop(expected_seq))
                        expected_seq += 1

                # Part 3: ACK riêng gói DATA vừa nhận,
                # không gửi cumulative ACK.
                sock.sendto(make_packet(ACK, seq_num), sender_address)

            elif packet_type == END:
                if seq_num == expected_seq and header.length == 0:
                    sock.sendto(
                        make_packet(ACK, seq_num + 1),
                        sender_address,
                    )
                    sys.stdout.buffer.write(message)
                    sys.stdout.buffer.flush()
                    return

                sock.sendto(
                    make_packet(ACK, expected_seq),
                    sender_address,
                )

    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("receiver_ip")
    parser.add_argument("receiver_port", type=int)
    parser.add_argument("window_size", type=int)
    args = parser.parse_args()

    receiver(args.receiver_ip, args.receiver_port, args.window_size)


if __name__ == "__main__":
    main()
