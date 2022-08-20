import socket
import os

TFTP_DEFAULT_PORT = 69

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
    

    def run(self):
        while True:
            bytes, address = self.socket.recvfrom(512)
            print(f"{bytes=}, {address=}")
            
            