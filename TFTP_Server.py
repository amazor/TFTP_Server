from functools import wraps
from io import BufferedReader
import logging
import opcode
import socket
import os
import threading
from typing import Callable
from Packet import ACKPacket, DATAPacket, PacketType, RRQPacket, getOpCode


TFTP_DEFAULT_PORT = 70
TFTP_MAX_DATA_SIZE = 512
TFTP_MAX_HEADER_SIZE = 4
ILLEGAL_PKT_RC = 0
FORMAT = """[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"""

# TODO make prettier logging output
logging.basicConfig(level=logging.DEBUG, format=FORMAT)


class TFTP_Server(object):
    def __init__(self,
                 ip_address: str = 'localhost',
                 listen_port: int = TFTP_DEFAULT_PORT,
                 working_directory: str = os.getcwd()):
        
        self.__INITIAL_REQUEST_CALLBACKS__ : dict[PacketType, Callable] = {}
        self.add_initial_request_callback(PacketType.RRQ, self.handle_read_request)
        self.add_initial_request_callback(PacketType.WRQ, self.handle_write_request)
        
        self.working_directory = working_directory
        self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.ip_address = ip_address
        self.listen_socket.bind((ip_address, listen_port))
        self.connection_sockets = {}
        
    def add_initial_request_callback(self, type, callback):
        self.__INITIAL_REQUEST_CALLBACKS__[type] = callback
                
    def bind_directory(self, directory: str) -> None:
        self.working_directory = directory
        
    def process_packet(self, opcode: PacketType, packet_args: tuple[bytes, str]) -> bool:
        """Process packet request and begin new thread for handling.

        Args:
            opcode (PacketType): The type of packet
            packet_args (tuple[bytes, str]): _description_

        Returns:
            bool: True if successful, false otherwise
        """
        # creates a new thread to handle the request based on the opcode of the packet
        t: threading.Thread
        
        logging.debug(f"Processing Packet {opcode=}")
        t = threading.Thread(target = self.__INITIAL_REQUEST_CALLBACKS__[opcode], args=packet_args)
            # logging.error(f"Unknown opcode {opcode}")
            # return False
        t.start()
        return True
    
    
    def verify_ack(self, packet, block_num, address, request_address)-> bool:
        ack_packet = ACKPacket.create_from_bytes(packet)
        logging.debug(f"Verifying ACK packet {ack_packet}")
        
        if ack_packet.block_num != block_num:
            logging.warning(f"Incorrect block_num")
            return False
        
        if address != request_address:
            logging.warning(f"ACK packet address mismatch {address} (expected {request_address})")
            return False
        
        return True 
        
        
    
    def send_file(self, filename, request_address, sock:socket.socket):
        block_num = 1
        dataPKT: DATAPacket
        dataBuffer: bytes
        prev_data_acked: bool = True

        with open(filename, 'rb') as f:
            logging.info(f"Succesfully opened file {filename}")
            while (dataBuffer := f.read(TFTP_MAX_DATA_SIZE)) and prev_data_acked:
                dataPKT = DATAPacket(block_num, dataBuffer)
                sock.sendto(dataPKT.create_bytes(), request_address)
                logging.debug(f"sent data packet {block_num} to {request_address}")
                (packet, address) = sock.recvfrom(TFTP_MAX_HEADER_SIZE + TFTP_MAX_DATA_SIZE)
                prev_data_acked = self.verify_ack(packet, block_num, address, request_address)
                logging.debug(f"Recieved ACK for packet {block_num} from {address}")

        
    def handle_read_request(self, packet, address):
        rrqPKT: RRQPacket
        
        logging.debug(f"Handling read request in thread {threading.get_ident()}")
        rrqPKT = RRQPacket.create_from_bytes(packet)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as new_socket:
            self.add_socket_connection(new_socket)
            self.send_file(rrqPKT.filename, address, new_socket)
            self.remove_socket_connection(new_socket)
            
            
    def remove_socket_connection(self, sock:socket.socket):
        port = sock.getsockname()[1]
        logging.debug(f"Removing socket connection {port}")
        del self.connection_sockets[port]
        
        
    def add_socket_connection(self, sock:socket.socket) -> int:
            sock.bind((self.ip_address, 0))
            port = sock.getsockname()[1]
            self.connection_sockets[port] = sock
            logging.debug(f"Adding socket connection to port {port}")
            return port        


    def handle_write_request(self, packet):
        logging.info(f"Handling write request in thread {threading.get_ident()}")
        pass

    def check_legal_packet(self, packet: bytes) -> int:
        """Check if a packet is a legal initial packet.

        Args:
            packet (bytes): bytes starting with TFTP Packet Header

        Returns:
            int: Positive number indicating packet type if successful, 0 otherwise
        """        
        opcode = getOpCode(packet)
        if opcode not in self.__INITIAL_REQUEST_CALLBACKS__ :
            logging.warning(f"Unknown TFTP Initial Packet operation: {opcode:02}")
            return ILLEGAL_PKT_RC
        return opcode
    
    def start_server(self):
        packet_type: PacketType
        
        while True:
            logging.info("TFTP_Server Waiting for packet")
            packet_args = (packet, address) = self.listen_socket.recvfrom(TFTP_MAX_HEADER_SIZE + TFTP_MAX_DATA_SIZE)
            packet_type = self.check_legal_packet(packet)
            if packet_type > 0:
                logging.info(f"TFTP_Server Recieved opcode {packet_type:02} from {address}")
                self.process_packet(packet_type, packet_args)
            else:
                logging.debug(f"Dropping Illegal Packet")
                
            