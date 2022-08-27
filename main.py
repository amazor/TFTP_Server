import logging
import socket
from TFTP_Server import TFTP_Server
import multiprocessing as mp
import Packet


def main():
    logging.basicConfig(level=logging.DEBUG)
    server = TFTP_Server()
    p = mp.Process(target=server.run)
    p.start()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        packet = Packet.create_RRQ_packet("test_filename", "test_mode")
        s.sendto(packet, ("localhost", 69))
        p.join()
        


if __name__ == '__main__':
    main()