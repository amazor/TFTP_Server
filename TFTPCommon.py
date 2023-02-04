from io import BufferedReader, BufferedWriter, TextIOWrapper
import os
import socket
from Packet import DATAPacket, ACKPacket, ERRORPacket, Error_Codes
import logging

TFTP_DEFAULT_PORT = 69
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

def send_file(filename:str, mode:str, request_address, sock:socket.socket):
    block_num = 1
    dataPKT: DATAPacket
    dataBuffer: bytes
    prev_data_acked: bool = True
    file : BufferedReader # or TextIOWrapper
    
    try:
        if mode == 'netascii':
            file = open(filename, 'r')
        else: # Assume octet if mode is not netascii
            file = open(filename, 'rb')
    except FileNotFoundError:
        logging.error(f"file not found: {filename}")
        errorPKT = ERRORPacket(Error_Codes.Not_Found_ERR, f"file not found: {filename}")
        sock.sendto(errorPKT.create_bytes(), request_address) 
        return 
    except IOError: # TODO: handle different windows/linux error codes
        logging.error(f"Error opening file: {filename}")
        errorPKT = ERRORPacket(Error_Codes.Access_ERR, f"Error opening file: {filename}")
        sock.sendto(errorPKT.create_bytes(), request_address) 
        return 
    try:
        while (dataBuffer := file.read(TFTP_MAX_DATA_SIZE)) and prev_data_acked:
            dataPKT = DATAPacket(block_num, dataBuffer)
            sock.sendto(dataPKT.create_bytes(), request_address)
            (packet, address) = sock.recvfrom(TFTP_MAX_PACKET_SIZE)
            prev_data_acked = verify_ack(packet, block_num, address, request_address)
            block_num += 1
    except UnicodeDecodeError as e:
        logging.error(e)
        errorPKT = ERRORPacket(Error_Codes.Not_Defined_ERR, f"Unicode Error, try using binary mode: {e}")
        sock.sendto(errorPKT.create_bytes(), request_address) 
    finally:
        file.close()

def receive_file(full_file_path:str, mode:str, request_address, sock:socket.socket, /, *, isServer=False):
    block_num: int = 0
    data_pkt: DATAPacket
    data_len: int
    is_data_left: bool = True
    file_dir: str = os.path.dirname(os.path.abspath(full_file_path))
    file: BufferedWriter # or TextIOWrapper
    
    if isServer:
        # Respond to initial request with ack
        ack_pkt = ACKPacket(block_num)
        sock.sendto(ack_pkt.create_bytes(), request_address)
    
    os.makedirs(file_dir, exist_ok=True)
    try:
        if mode == 'netascii':
            file = open(full_file_path, 'w')
        else: # Assume octet if mode is not netascii
            file = open(full_file_path, 'wb')
    except FileNotFoundError:
        logging.error(f"file not found: {full_file_path}")
        errorPKT = ERRORPacket(Error_Codes.Not_Found_ERR, f"file not found: {full_file_path}")
        sock.sendto(errorPKT.create_bytes(), request_address) 
        return 
    except OSError: # TODO: handle different windows/linux error codes
        logging.error(f"Error opening file: {full_file_path}")
        errorPKT = ERRORPacket(Error_Codes.Access_ERR, f"Error opening file: {full_file_path}")
        sock.sendto(errorPKT.create_bytes(), request_address) 
        return 
    try:
        while is_data_left:
            block_num += 1
            (data_bytes, addr) = sock.recvfrom(TFTP_MAX_PACKET_SIZE)
            data_pkt = DATAPacket.create_from_bytes(data_bytes)
            verify_data(data_pkt, block_num, addr, request_address)
                
            file.write(data_pkt.data)
            sock.sendto(ACKPacket(block_num).create_bytes(), addr)
            data_len = len(data_pkt.data)
            is_data_left = data_len == TFTP_MAX_DATA_SIZE
    except UnicodeDecodeError as e:
        logging.error(e)
        errorPKT = ERRORPacket(Error_Codes.Not_Defined_ERR, f"Unicode Error, try using binary mode: {e}")
        sock.sendto(errorPKT.create_bytes(), request_address) 
    finally:
        file.close()