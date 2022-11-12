import os
import socket
from Packet import DATAPacket, ACKPacket

TFTP_DEFAULT_PORT = 70
TFTP_MAX_DATA_SIZE = 512
TFTP_MAX_HEADER_SIZE = 4
TFTP_MAX_PACKET_SIZE = TFTP_MAX_HEADER_SIZE + TFTP_MAX_DATA_SIZE


def verify_ack(packet, block_num, address, request_address) -> bool:
    ack_packet = ACKPacket.create_from_bytes(packet)
    if ack_packet.block_num != block_num:
        return False
    if address != request_address:
        return False
    return True 

def verify_data(packet: DATAPacket, block_num:int, address, request_address) -> bool:
    if packet.block_num != block_num:
        return False
    if address != request_address:
        return False
    return True 

def send_file(filename, request_address, sock:socket.socket):
    block_num = 1
    dataPKT: DATAPacket
    dataBuffer: bytes
    prev_data_acked: bool = True
    
    with open(filename, 'rb') as f:
        while (dataBuffer := f.read(TFTP_MAX_DATA_SIZE)) and prev_data_acked:
            dataPKT = DATAPacket(block_num, dataBuffer)
            sock.sendto(dataPKT.create_bytes(), request_address)
            (packet, address) = sock.recvfrom(TFTP_MAX_PACKET_SIZE)
            prev_data_acked = verify_ack(packet, block_num, address, request_address)
            block_num += 1

def receive_file(full_file_path, request_address, sock:socket.socket, /, *, isServer=False):
    block_num: int = 0
    data_pkt: DATAPacket
    data_len: int
    is_data_left: bool = True
    file_dir: str = os.path.dirname(os.path.abspath(full_file_path))
    
    if isServer:
        # Respond to initial request with ack
        ack_pkt = ACKPacket(block_num)
        sock.sendto(ack_pkt.create_bytes(), request_address)
    
    os.makedirs(file_dir, exist_ok=True)
        
    with open(os.path.join(file_dir, full_file_path), 'wb') as f:
        while is_data_left:
            block_num += 1
            (data_bytes, addr) = sock.recvfrom(TFTP_MAX_PACKET_SIZE)
            data_pkt = DATAPacket.create_from_bytes(data_bytes)
            verify_data(data_pkt, block_num, addr, request_address)
                
            f.write(data_pkt.data)
            sock.sendto(ACKPacket(block_num).create_bytes(), addr)
            data_len = len(data_pkt.data)
            is_data_left = data_len == TFTP_MAX_DATA_SIZE