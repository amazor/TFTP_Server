from TFTP_Server import TFTP_DEFAULT_PORT, TFTP_MAX_DATA_SIZE, TFTP_MAX_HEADER_SIZE, TFTP_Server
import logging
import socket
import multiprocessing as mp
import Packet
import TFTP_Client
import os


def main():
    data_size: int
    Packet.DATAPacket
    logging.basicConfig(level=logging.DEBUG)
    server = TFTP_Server()
    p = mp.Process(target=server.start_server)
    p.start()
    os.chdir("./client_dir")
    TFTP_Client.start_read("localhost", "localhost", "README.md", "stub")     
    p.join()   


if __name__ == '__main__':
    main()