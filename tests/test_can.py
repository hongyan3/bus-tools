from libs.can.device_tosun import TosunDevice
from modules.can_fuzz import random_fuzz
import time
import threading

MIN_ARB = 0x000
MAX_ARB = 0xFFF
delay = 1

def monitor(bus: TosunDevice):
    timeout = 1
    flags = {
        0x670: 0,
        0x672: 0,
        0x675: 0
    }
    while True:
        try:
            # print('[info] Start heartbeat detection.')
            bus.send(arb_id=0x7ff, data=[0x02, 0x10, 0x01])
            end_time = time.time() + timeout
            while time.time() < end_time:
                res = bus.recv()
                if res is not None and res.arbitration_id in flags:
                    flags[res.arbitration_id] = 1
            for key, value in flags.items():
                if value != 1:
                    flags[key] -= 1
                    if flags[key] <= -3:
                        print(f'\n[info] ecu: 0x{key:02x} 3 times unresponsive')
                        flags[key] = 0
                else:
                    flags[key] = 0
            time.sleep(3)
        except Exception as e:
            print(f'\n[error] Someing error: {e}')

if __name__=='__main__':
    bus = TosunDevice()
    heartbeat = threading.Thread(target=monitor, args={bus,}, daemon=True)
    heartbeat.start()
    random_fuzz(device=bus)