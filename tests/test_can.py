from libs.can.device_tosun import TosunDevice

with TosunDevice() as bus:
    while True:
        res = bus.recv(timeout=1)
        if res is not None:
            print(res)