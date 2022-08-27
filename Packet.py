from abc import ABC
from dataclasses import dataclass
from enum import Enum
from mimetypes import init
import struct


class OpCode(Enum):
    RRQ   = 1
    WRQ   = 2
    DATA  = 3
    ACK   = 4
    ERROR = 5
    
def getOpCode(packet:bytes):
    return struct.unpack("!H", packet[0:2])[0]

def create_RRQ_packet(filename:str, mode:str)-> bytes:
    struct_format = "! H {}s x {}s x".format(len(filename), len(mode))
    return struct.pack(struct_format, OpCode.RRQ.value, filename.encode(), mode.encode())