import os
import sys
import time
from doipclient import DoIPClient

DIAG_LOGICAL_ADDRESS = 0x0E80

def DoipConnect(ecu_logical_address: int) -> DoIPClient:
    try:
        address, announcement = DoIPClient.await_vehicle_announcement(timeout=5)
    except TimeoutError:
        print('[error] Connection timed out, please check your cable or network settings.')
        sys.exit(1)
    time.sleep(0.5)
    cdm_logical_address = announcement.logical_address
    cdm_ip, cdm_doip_port = address
    # print("[info] CDM/VGM info: ", cdm_ip, hex(cdm_logical_address), cdm_doip_port)
    client = DoIPClient(ecu_ip_address=cdm_ip, ecu_logical_address=ecu_logical_address, client_logical_address=DIAG_LOGICAL_ADDRESS)
    return client

class DoIPConnection:
    DIAG_LOGICAL_ADDRESS = 0x0E80

    def __init__(self, ecu_address: int):
        address, announcement = DoIPClient.await_vehicle_announcement(timeout=5)
        cdm_logical_address = announcement.logical_address
        cdm_ip, cdm_doip_port = address
        # print("[info] CDM/VGM info: ", cdm_ip, hex(cdm_logical_address), cdm_doip_port)
        self._client = DoIPClient(ecu_ip_address=cdm_ip, ecu_logical_address=ecu_address, client_logical_address=self.DIAG_LOGICAL_ADDRESS)
        self.info = {
            "diag_ip": cdm_ip,
            "diag_port": cdm_doip_port,
            "logical_address": f'0x{cdm_logical_address:02x}',
        }
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
    
    def close(self):
        self._client.close()

    def send(self, command: int | str | bytes, timeout=2) -> bytes:
        """
        command: 0x22F190 | '22F190' | b'22F190'
        """
        cmd = None
        if isinstance(command, int):
            byte_length = (command.bit_length() + 7) // 8
            cmd = command.to_bytes(byte_length, byteorder='big')
        elif isinstance(command, str):
            cmd = bytes.fromhex(command)
        elif isinstance(command, bytes):
            cmd = command
        else:
            raise TypeError('Unsupported parameter type')
        self._client.send_diagnostic(cmd, timeout=timeout)
        res = self._client.receive_diagnostic(timeout)
        return res