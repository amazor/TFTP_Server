import socket

import Packet
from TFTP_Server import TFTP_DEFAULT_PORT, TFTP_MAX_DATA_SIZE, TFTP_MAX_HEADER_SIZE


def start_read(from_addr, to_addr, filename, mode):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        # send initial request
        s.bind((from_addr, 0))
        packet = Packet.create_ReadRequest_packet(filename, mode)
        s.sendto(packet, (to_addr, TFTP_DEFAULT_PORT))
        packet_size = TFTP_MAX_HEADER_SIZE + TFTP_MAX_DATA_SIZE
        
        # Data and Ack loop
        with open(filename, "wb") as f:
            print("opened new file: " + filename)
            while packet_size == TFTP_MAX_HEADER_SIZE + TFTP_MAX_DATA_SIZE:
                (packet, addr) = s.recvfrom(TFTP_MAX_HEADER_SIZE + TFTP_MAX_DATA_SIZE)
                print("received data packet" )
                packet_size = len(packet)
                data_pkt = Packet.DATAPacket.create_from_bytes(packet)
                f.write(data_pkt.data)
                s.sendto(Packet.ACKPacket(data_pkt.block_num).create_bytes(), addr)
                print("sent ACK packet")