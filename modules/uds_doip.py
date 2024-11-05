import argparse
import json
import os
import re
from libs.doip import service
from libs.doip.client import DoIPConnection

PINCODE = {}

ECU = {
    "DHU": 0x1201,
    "TCAM": 0x1011,
    "RDHU": 0x1205
}

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
    
def open_debug(ecu_name: str, state=True):
    """
    ecu_name:
    - DHU
    - TCAM
    state:
    - True: OPEN
    - FALSE CLOSE
    """
    vin = vin_code()
    try:
        ecu_address = ECU[ecu_name]
        pincode = PINCODE[vin][ecu_name]
    except KeyError as e:
        print('[error] Cannot found the pincode or ecu address')
        return
    client = DoIPConnection(ecu_address)
    try:
        if ecu_name == 'DHU' or ecu_name == 'RDHU':
            service.unlock_27service(client=client, pincode=pincode)
            res = None
            if state:
                res = client.send('2EC03E01')
            else:
                res = client.send('2EC03E00')
            if res[0] == 0x6E:
                print(f'[info] {'Open' if state else 'Close'} {ecu_name} debug mode successfully')
            else:
                print(f'[error] {'Open' if state else 'Close'} {ecu_name} debug mode failed')
        elif ecu_name == 'TCAM':
            open_cmd = ['31010232', '3101023000', '3101DC01']
            close_cmd = ['31020232', '3102023200', '3102DC01']
            service.unlock_27service(client=client, pincode=pincode)
            res = None
            flag = False
            if state:
                for cmd in open_cmd:
                    res = client.send(cmd)
                    if res[0] == 0x71:
                        print(f'[info] {'Open' if state else 'Close'} {ecu_name} debug mode successfully')
                        flag = True
                        break
                if not flag:
                    print(f'[error] {'Open' if state else 'Close'} {ecu_name} debug mode failed')
            else:
                for cmd in close_cmd:
                    res = client.send(cmd)
                    if res[0] == 0x71:
                        print(f'[info] {'Open' if state else 'Close'} {ecu_name} debug mode successfully')
                        flag = True
                        break
                if not flag:
                    print(f'[error] {'Open' if state else 'Close'} {ecu_name} debug mode failed')
        else:
            print(f'Unsupported the ecu: {ecu_name}')

    finally:
        client.close()

if __name__=='__main__':
    pincode_file = 'config/pincode.json'
    with open(pincode_file, 'r') as file:
        PINCODE = json.load(file)
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='module')

    # debug module
    debug_parser = subparsers.add_parser('debug', help='Open or close the debug mode')
    debug_parser.add_argument('--ecu', '-e', type=str, help='Input ecu name')
    debug_parser.add_argument('state', choices=['open', 'close'])

    # console module
    info_parser = subparsers.add_parser('console', help='Enter terminal')
    
    args = parser.parse_args()

    if args.module == 'debug':
        ecu_name = args.ecu
        state = True if args.state == 'open' else False
        open_debug(ecu_name=ecu_name, state=state)
    elif args.module == 'console':
        console()
