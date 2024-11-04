import os
import re
from libs.doip import service
from libs.doip.client import DoIPConnection

def vin_code() -> str:
    cdm_address = 0x1001
    with DoIPConnection(cdm_address) as client:
        res = client.send('22F190')
        payload = res[3:]
        return payload.decode()

def console():
    GREEN = "\033[32m"
    BLUE = "\033[96m"
    RESET = "\033[0m"
    RED = "\033[31m"

    ecu_address = None
    help_info = """
Example:
    console> set ecu=1201
    ecu_1201> 22 F1 90
    ecu_1201> 62 F1 90 FF FF
Command:
    set ecu=<ecu_address>   # Example: set ecu=1201
    exit                    # Exit program
    clear                   # Clear screen output
    """
    pattern = r'^(([0-9A-Fa-f]{2})\s)*([0-9A-Fa-f]{2})$'
    client = DoIPConnection(0x1FFF)
    try:
        while True:
            if ecu_address is None:
                print(f'{BLUE}console{RESET}> ', end="")
            else:
                print(f'{BLUE}ecu_{ecu_address}{RESET}> ', end="")
            command = input().strip()
            if command == 'help':
                print(help_info)
            elif command == 'exit':
                return
            elif command == 'clear':
                os.system('clear')
            elif command.startswith('set ecu='):
                ecu_address=command.split('=')[1]
                addr = int(ecu_address, 16)
                client.close()
                client = DoIPConnection(addr)
            elif re.match(pattern, command) is not None:
                if ecu_address is None:
                    print('Please set the ecu logical address. Example: set ecu=<ecu_address>')
                    continue
                try:
                    hex_strings = command.split(' ')
                    cmd = bytes.fromhex(''.join(hex_strings))
                    raw = client.send(cmd, timeout=5)
                    res = raw.hex()
                    formatted_string = ' '.join(res[i:i+2].upper() for i in range(0, len(res), 2))
                    if raw[0] == 0x7F:
                        print(f'{RED}Negative{RESET}: {formatted_string}')
                        print(f'Message: {service.NRC[raw[-1]]}')
                    else:
                        print(f'{GREEN}Positive{RESET}: {formatted_string}')
                except TimeoutError:
                    print('Send or receive timeout')
                except Exception as e:
                    print(f'{RED}Error{RESET}: {e}')
            else:
                print('Invalid command, please enter "help"')
    except KeyboardInterrupt:
        print('\nexit')
    finally:
        client.close()
    
def open_debug():
    client = DoIPConnection(0x1201)
    try:
        service.unlock_27service(client=client, pincode='FFFFFFFFFF')
        res = client.send('2EC03E01')
        if res[0] == 0x6E:
            print('[info] Open debug mode successfully')
        else:
            print('[error] Open debug mode failed')
    finally:
        client.close()

if __name__=='__main__':
    print(vin_code())
