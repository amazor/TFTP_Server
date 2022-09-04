import logging
import socket
import os
import threading
from Packet import DATAPacket, PacketType, RRQPacket, getOpCode


TFTP_DEFAULT_PORT = 70
TFTP_MAX_DATA_SIZE = 512
TFTP_MAX_HEADER_SIZE = 4
ILLEGAL_PKT_RC = -1

# TODO make prettier logging output
logging.basicConfig(level=logging.DEBUG)


class TFTP_Server(object):
    def __init__(self,
                 ip_address: str = 'localhost',
                 listen_port: int = TFTP_DEFAULT_PORT,
                 working_directory: str = os.getcwd()):
        
        self.working_directory = working_directory
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((ip_address, listen_port))
        
                
    def bind_directory(self, directory: str) -> None:
        self.working_directory = directory
        
    def process_packet(self, opcode, packet_args):
        t: threading.Thread
        if opcode == PacketType.RRQ:
            t = threading.Thread(target = self.handle_read_request, args=packet_args)
        elif opcode == PacketType.WRQ:
            t = threading.Thread(target = self.handle_write_request, args=packet_args)

        else:
            print(f"Unknown opcode {opcode}")
            
        t.start()

    
    def handle_read_request(self, packet, address):
        rrqPKT: RRQPacket
        dataPKT: DATAPacket
        # TODO create better log for thread
        logging.info(f"Handling read request in thread {threading.get_ident()}")
        rrqPKT = RRQPacket.create_from_bytes(packet)
        logging.info(f"{rrqPKT=}")
        block_num = 1
        with open(rrqPKT.filename, 'rb') as f:
            data = f.read(TFTP_MAX_DATA_SIZE)
            dataPKT = DATAPacket(block_num, data)
            self.socket.sendto(dataPKT.create_bytes(), address)
            
            


    def handle_write_request(self, packet):
        logging.info(f"Handling write request in thread {threading.get_ident()}")        

    def check_legal_packet(self, packet: bytes):
        packetType = getOpCode(packet)
        if packetType != PacketType.RRQ and packetType != PacketType.WRQ:
            logging.warning("Invalid Request Operation")
            return ILLEGAL_PKT_RC
        return packetType
    
    def start_server(self):
        while True:
            logging.debug("TFTP_Server Waiting for packet")
            packet_args = (packet, address) = self.socket.recvfrom(TFTP_MAX_HEADER_SIZE + TFTP_MAX_DATA_SIZE)
            packetType = self.check_legal_packet(packet)
            self.process_packet(packetType, packet_args)

            