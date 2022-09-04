from TFTP_Server import TFTP_DEFAULT_PORT, TFTP_MAX_DATA_SIZE, TFTP_MAX_HEADER_SIZE, TFTP_Server
import logging
import socket
import multiprocessing as mp
import Packet


def main():
    logging.basicConfig(level=logging.DEBUG)
    server = TFTP_Server()
    p = mp.Process(target=server.start_server)
    p.start()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        packet = Packet.create_ReadRequest_packet("README.md", "stub_mode")
        s.sendto(packet, ("localhost", TFTP_DEFAULT_PORT))
        print(s.recvfrom(TFTP_MAX_HEADER_SIZE + TFTP_MAX_DATA_SIZE))
        p.join()
        


if __name__ == '__main__':
    main()