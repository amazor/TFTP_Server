import logging
import socket
import os
import threading
import Packet


TFTP_DEFAULT_PORT = 69
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
        
    def handle_request(self, opcode, packet):
        if opcode == Packet.OpCode.RRQ.value:
            t = threading.Thread(target = self.handle_read_request(), args=(packet,))
        elif opcode == Packet.OpCode.WRQ.value:
            threading.Thread(target = self.hand_write_request(), args=(packet,))

        else:
            print(f"Unknown opcode {opcode}")
            
        t.start()

    
    def handle_read_request(packet):
        logging.info(f"Handling read request in thread {threading.get_ident()}")
    def hand_write_request(packet):
        logging.info(f"Handling write request in thread {threading.get_ident()}")
        

    def run(self):
        while True:
            logging.debug("TFTP_Server Waiting for packet")
            bytes, address = self.socket.recvfrom(512)
            opcode = Packet.getOpCode(bytes)
            if opcode != Packet.OpCode.RRQ.value and opcode != Packet.OpCode.WRQ.value:
                logging.warning("Invalid Request Operation")
            self.handle_request(opcode, bytes)
            