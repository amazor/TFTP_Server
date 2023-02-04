"""This file provides convenience methods for client request and response processing.
    It will be replaced with a robust TFTPClient in the future.
"""
import socket
import Packet
import TFTPCommon

def read(from_addr, to_addr, filename, mode):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        packet_size: int = TFTPCommon.TFTP_MAX_PACKET_SIZE
        
        # send initial request
        sock.bind(from_addr)
        rrq_pkt = Packet.RRQPacket(filename, mode)
        sock.sendto(rrq_pkt.create_bytes(), to_addr)
        
        # Recieve Data and send Ack loop
        TFTPCommon.receive_file(filename, mode, to_addr, sock, isServer=False)
        # with open(filename, "wb") as f:
        #     print("opened new file: " + filename)
        #     while packet_size == TFTPCommon.TFTP_MAX_PACKET_SIZE:
        #         (packet, addr) = s.recvfrom(TFTPCommon.TFTP_MAX_PACKET_SIZE)
        #         print("received data packet" )
        #         packet_size = len(packet)
        #         data_pkt = Packet.DATAPacket.create_from_bytes(packet)
        #         f.write(data_pkt.data)
        #         s.sendto(Packet.ACKPacket(data_pkt.block_num).create_bytes(), addr)
        #         print("sent ACK packet")

def write(from_addr, to_addr, filename, mode):
        print(filename)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            packet_size: int = TFTPCommon.TFTP_MAX_HEADER_SIZE + TFTPCommon.TFTP_MAX_DATA_SIZE
            
            sock.bind(from_addr)
            
            # send initial request
            wrq_pkt = Packet.WRQPacket(filename, mode)
            sock.sendto(wrq_pkt.create_bytes(), to_addr)
            
            (pkt, addr) = sock.recvfrom(packet_size)
            
            #assume packet is ACK packet
            TFTPCommon.send_file(filename, mode, addr, sock)
