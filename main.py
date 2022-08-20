import socket
from TFTP_Server import TFTP_Server
import multiprocessing as mp

def main():
    server = TFTP_Server()
    p = mp.Process(target=server.run)
    p.start()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto("Test Amir".encode(), ("localhost", 69))
        p.join()
        


if __name__ == '__main__':
    main()