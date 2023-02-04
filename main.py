from TFTP_Server import TFTP_DEFAULT_PORT, TFTP_Server
import multiprocessing as mp
import TFTP_Client
import os

def test_server_get(from_addr, to_addr) -> bool:
    TFTP_Client.read(from_addr, to_addr, "server_doc.txt", "octet")     

def test_server_put(from_addr, to_addr) -> bool:
    TFTP_Client.write(from_addr, to_addr, "client_doc.txt", "octet")     
    
    
def main():
    from_addr = ("localhost", 0)
    to_addr = ("localhost", TFTP_DEFAULT_PORT)
    
    # Begin TFTP server as a seperate process
    # TFTP_Server(ip_address, listen_port, working_directory)
    server = TFTP_Server(working_directory = os.path.join(os.getcwd(), "server_dir")) 
    p = mp.Process(target=server.start_server)
    p.start()
    
    os.chdir("./client_dir")

    test_server_get(from_addr, to_addr)
    test_server_put(from_addr, to_addr)
    p.join()

if __name__ == '__main__':
    main()