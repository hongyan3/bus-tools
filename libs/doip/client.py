import os
import sys
import time
from doipclient import DoIPClient

DIAG_LOGICAL_ADDRESS = 0x0E80

def DoipConnect(ecu_logical_address: int) -> DoIPClient:
    try:
        address, announcement = DoIPClient.await_vehicle_announcement(timeout=2)
    except TimeoutError:
        print('[error] Connection timed out, please check your cable or network settings.')
        sys.exit(1)
    time.sleep(0.5)
    cdm_logical_address = announcement.logical_address
    cdm_ip, cdm_doip_port = address
    # print("[info] CDM/VGM info: ", cdm_ip, hex(cdm_logical_address), cdm_doip_port)
    client = DoIPClient(ecu_ip_address=cdm_ip, ecu_logical_address=ecu_logical_address, client_logical_address=DIAG_LOGICAL_ADDRESS)
    return client