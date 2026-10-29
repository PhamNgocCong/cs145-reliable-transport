
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


def wait_for_ack(sock, destination, packet, expected_ack):
    while True:
        sock.sendto(packet, destination)
        deadline = time.monotonic() + TIMEOUT

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break

            sock.settimeout(remaining)
            try:
                response, _ = sock.recvfrom(2048)
            except socket.timeout:
                break

            if parse_ack(response) == expected_ack:
                return


def sender(receiver_ip, receiver_port, window_size):
    if window_size <= 0:
        raise ValueError("window_size must be greater than zero")

    message = sys.stdin.buffer.read()
    chunks = [
        message[i:i + MAX_PAYLOAD_SIZE]
        for i in range(0, len(message), MAX_PAYLOAD_SIZE)
    ]

    destination = (receiver_ip, receiver_port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        # START handshake
        wait_for_ack(
            sock, destination, make_packet(START, 0), 1
        )

        packets = {
            i + 1: make_packet(DATA, i + 1, chunk)
            for i, chunk in enumerate(chunks)
        }

        total = len(chunks)
        base = 1
        next_seq = 1
        acknowledged = set()
        timer_start = None

        while base <= total:
            # Fill the current sending window.
            while (
                next_seq <= total
                and next_seq < base + window_size
            ):
                sock.sendto(packets[next_seq], destination)
                next_seq += 1

                if timer_start is None:
                    timer_start = time.monotonic()

            if base > total:
                break

            if timer_start is None:
                timer_start = time.monotonic()

            remaining = TIMEOUT - (time.monotonic() - timer_start)

            if remaining <= 0:
                # Retransmit only unacknowledged packets.
                for seq in range(base, next_seq):
                    if seq not in acknowledged:
                        sock.sendto(packets[seq], destination)

                timer_start = time.monotonic()
                continue

            sock.settimeout(remaining)

            try:
                response, _ = sock.recvfrom(2048)
            except socket.timeout:
                continue

            ack_num = parse_ack(response)

            # RTP-opt: DATA ACK identifies the individual packet.
            if (
                ack_num is not None
                and base <= ack_num < next_seq
            ):
                acknowledged.add(ack_num)

                old_base = base
                while base in acknowledged:
                    acknowledged.remove(base)
                    base += 1

                if base != old_base:
                    timer_start = (
                        time.monotonic() if base < next_seq else None
                    )

        # END: the specification permits exiting after 500 ms
        # if the END ACK is lost.
        end_seq = total + 1
        end_packet = make_packet(END, end_seq)
        sock.sendto(end_packet, destination)

        deadline = time.monotonic() + TIMEOUT
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break

            sock.settimeout(remaining)
            try:
                response, _ = sock.recvfrom(2048)
            except socket.timeout:
                break

            if parse_ack(response) == end_seq + 1:
                break

    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("receiver_ip")
    parser.add_argument("receiver_port", type=int)
    parser.add_argument("window_size", type=int)
    args = parser.parse_args()

    sender(args.receiver_ip, args.receiver_port, args.window_size)


if __name__ == "__main__":
    main()
