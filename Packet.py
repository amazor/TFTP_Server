from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import IntEnum
import struct

#Internal Definitions
class __OpCode(IntEnum):
    RRQ   = 1
    WRQ   = 2
    DATA  = 3
    ACK   = 4
    ERROR = 5
DATA_TRANSFER_PACKET_STRUCT = struct.Struct("! H H")

#External Definitions
PacketType = __OpCode
OPCODE_SIZE = 2

@dataclass(init=False)
class Packet(ABC):
    opcode: PacketType = field(init=False, repr=False) 
    
    @abstractmethod
    def create_bytes(self):
        ...
    
    @classmethod
    @abstractmethod
    def create_from_bytes(cls):
        ...
     
    
@dataclass
class RRQPacket(Packet):
    filename : str
    mode : str
    
    def __post_init__(self):
        self.opcode = PacketType.RRQ
    
    def create_bytes(self) -> bytes:
        return create_ReadRequest_packet(self.filename, self.mode)
    
    @classmethod    
    def create_from_bytes(cls, b: bytes):
        return read_ReadRequest_packet(b)
        
@dataclass
class DATAPacket(Packet):
    block_num : int
    data : bytes
    
    def __post_init__(self):
        self.opcode = PacketType.DATA
    
    def create_bytes(self) -> bytes:
        return create_Data_packet(self.block_num, self.data)
    
    @classmethod    
    def create_from_bytes(cls, b: bytes):
        _, block_num = DATA_TRANSFER_PACKET_STRUCT.unpack(b[0:4])
        data = b[4:]
        return cls(block_num, data)

@dataclass
class ACKPacket(Packet):
    block_num : int
    
    def __post_init__(self):
        self.opcode = PacketType.ACK
    
    def create_bytes(self) -> bytes:
        return create_Ack_packet(self.block_num)
    
    @classmethod    
    def create_from_bytes(cls, b: bytes):
        _, block_num = DATA_TRANSFER_PACKET_STRUCT.unpack(b[0:4])
        return cls(block_num)
    
    
def getOpCode(packet:bytes) -> int:
    return struct.unpack("!H", packet[0:2])[0]

def create_ReadRequest_packet(filename:str, mode:str) -> bytes:
    struct_format = "! H {}s x {}s x".format(len(filename), len(mode))
    return struct.pack(struct_format, __OpCode.RRQ, filename.encode(), mode.encode())

def create_WriteRequest_packet(filename:str, mode:str) -> bytes:
    struct_format = "! H {}s x {}s x".format(len(filename), len(mode))
    return struct.pack(struct_format, __OpCode.WRQ, filename.encode(), mode.encode())

def create_Data_packet(block_num:int, data:bytes) -> bytes:
    return DATA_TRANSFER_PACKET_STRUCT.pack(__OpCode.DATA, block_num) + data

def create_Ack_packet(block_num:int) -> bytes:
    return DATA_TRANSFER_PACKET_STRUCT.pack(__OpCode.ACK, block_num)

def create_Error_packet(error_code:int, error_msg:str) -> bytes:
    struct_format = "! H H x {}s x".format(len(error_msg))
    return struct.pack(struct_format, PacketType.ERROR, error_code, error_msg.encode())

def read_ReadRequest_packet(packet:bytes) -> RRQPacket:
    file_name : bytes
    mode: bytes
    (file_name, mode, empty_string) = packet[OPCODE_SIZE:].split(b'\0', maxsplit=2)
    # TODO: assert empty_string is truly empty
    return RRQPacket(file_name.decode(), mode.decode())