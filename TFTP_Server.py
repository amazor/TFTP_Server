import logging
import socket
import os
import threading
from typing import Callable
from Packet import PacketType, RRQPacket, WRQPacket, getOpCode, TFTP_OPCODE_STR_TBL

from TFTPCommon import TFTP_DEFAULT_PORT, TFTP_MAX_PACKET_SIZE
import TFTPCommon

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
        self.add_initial_request_callback(PacketType.RRQ, self._handle_read_request)
        self.add_initial_request_callback(PacketType.WRQ, self._handle_write_request)
        self.working_directory: str
        
        self.bind_directory(os.path.abspath(working_directory))
        self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.ip_address = ip_address
        self.listen_socket.bind((ip_address, listen_port))
        self.connection_sockets = {}

    def __remove_socket_connection(self, sock:socket.socket):
        port = sock.getsockname()[1]
        logging.debug(f"Removing socket connection {port}")
        del self.connection_sockets[port]
        
        
    def __add_socket_connection(self, sock:socket.socket) -> int:
            sock.bind((self.ip_address, 0))
            port = sock.getsockname()[1]
            self.connection_sockets[port] = sock
            logging.debug(f"Adding socket connection to port {port}")
            return port   
        
    def add_initial_request_callback(self, type, callback):
        self.__INITIAL_REQUEST_CALLBACKS__[type] = callback
                
    def bind_directory(self, directory: str) -> None:
        self.working_directory = directory
        
    def __process_packet(self, packet_args: tuple[bytes, str]) -> bool:
        """Process packet request and begin new thread for handling.

        Args:
            packet_args (tuple[bytes, str]): a tuple of bytes representing the packet and 

        Returns:
            bool: True if successful, false otherwise
        """
        t: threading.Thread
        opcode: int
        packet: bytes
        address: str
        
        # unpack packet args
        packet, address = packet_args
        
        logging.debug("Checking Packet Legality...")
        opcode = self.__check_legal_packet(packet)
        if opcode > 0:
            logging.debug("Packet is Legal")
            logging.info(f"Recieved packet type {opcode:02}[{TFTP_OPCODE_STR_TBL[opcode]}] from {address}")
            try:
                # creates a new thread to handle the request based on the opcode of the packet
                t = threading.Thread(target = self.__INITIAL_REQUEST_CALLBACKS__[opcode], args=packet_args)
                t.start()
            except KeyError:
                logging.error(f"No such opcode '{opcode}' in __INITIAL_REQUEST_CALLBACKS__")
                return False
            except Exception as e:
                logging.error(e)
                print(e)
                return False
            return True
        else:
            logging.debug(f"Dropping Illegal Packet from {address}")
            
    
    
    # TODO figure out how to support name mangling for inheritance (__ instead of _)
    def _handle_read_request(self, packet:bytes, address):
        rrqPKT: RRQPacket
        
        logging.debug(f"Handling read request in thread {threading.get_ident()}")
        rrqPKT = RRQPacket.create_from_bytes(packet)
        
        # Create new socket connection to handle read request
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as new_socket:
            self.__add_socket_connection(new_socket)
            TFTPCommon.send_file(os.path.join(self.working_directory, rrqPKT.filename) , address, new_socket)
            self.__remove_socket_connection(new_socket)     
            
    # TODO figure out how to support name mangling for inheritance (__ instead of _)
    def _handle_write_request(self, packet, address):
        wrqPKT: WRQPacket
        
        logging.info(f"Handling write request in thread {threading.get_ident()}")        
        wrqPKT = WRQPacket.create_from_bytes(packet)
        
        # Create new socket connection to handle read request
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as new_socket:
            self.__add_socket_connection(new_socket)
            TFTPCommon.receive_file(os.path.join(self.working_directory, wrqPKT.filename), address, new_socket, isServer=True)
            self.__remove_socket_connection(new_socket)     

    def __check_legal_packet(self, packet: bytes) -> int:
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
        while True:
            logging.info("TFTP_Server Waiting for Packet")
            # packet_args is a tuple representing the packet contents and the address from which the packet was received
            # We unpack this tuple to check the legality of packet contents 
            packet_args = self.listen_socket.recvfrom(TFTP_MAX_PACKET_SIZE)
            logging.debug("Packet Recieved")
            self.__process_packet(packet_args)

                
            