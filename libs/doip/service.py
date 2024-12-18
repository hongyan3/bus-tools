import struct
import time
from libs.doip.client import DoIPConnection

NRC = {
    0x11:'ServiceNotSupported/服务不支持, 诊断仪发送的请求消息中服务标识符无法识别或不支持',
    0x12:'SubFunctionNotSupported/不支持子服务, 诊断仪发送的请求消息中子服务无法识别或不支持',
    0x13:'IncorrectMessageLengthOrInvalidFormat/不正确的消息长度或无效的格式, 请求消息长度与特定服务规定的长度不匹配或者是参数格式与特定服务规定的格式不匹配',
    0x21:'BusyRepeatRequest/重复请求忙, 表明ECU太忙而不能去执行请求。一般来说, 在这种情况下, 诊断仪应进行重复请求工作',
    0x22:'conditionsNotCorrect/条件不正确, 表明ECU的状态条件不允许支持该请求',
    0x24:'requestSequenceError/请求序列错误, 表明收到的是非预期的请求消息序列',
    0x25:'noResponseFromSubnetComponent/子网节点无应答, 表明ECU收到请求, 但所请求的操作无法执行',
    0x26:'failurePreventsExecutionOfRequestedAction/故障阻值请求工作执行, 表明请求的动作因一故障原因而没有执行',
    0x31:'requestOutOfRange/请求超出范围, 请求消息包含一个超出允许范围的参数, 或者是不支持的数据标识符/例程标识符的访问',
    0x33:'securityAccessDenied/安全访问拒绝, 诊断仪无法通过ECU的安全策略',
    0x35:'invalidKey/密钥无效, 诊断仪发送的密钥与ECU内存中的密钥不匹配',
    0x36:'exceedNumberOfAttempts/超出尝试次数, 诊断仪尝试获得安全访问失败次数超过了ECU安全策略允许的值',
    0x37:'requiredTimeDelayNotExpired/所需时间延迟未到, 在ECU所需的请求延迟时间过去之前诊断仪又执行了一次请求',
    0x70:'uploadDownloadNotAccepted/不允许上传下载, 表明试图向ECU内存上传/下载数据失败的原因是条件不允许',
    0x71:'transferDataSuspended/数据传输暂停, 表明由于错误导致数据传输操作的中止',
    0x72:'generalProgrammingFailure/一般编程失败, 表明在不可擦除的内存设备中进行擦除或编程时ECU检测到错误发生',
    0x73:'wrongBlockSequenceCounter/错误的数据块序列计数器, ECU在数据块序列计数序列中检测到错误发生',
    0x78:'requestCorrectlyReceived-ResponsePending/正确接收请求消息-等待响应 表明ECU正确接收到请求消息, 但是将执行的动作未完成且ECU未准备好接收其它请求',
    0x7E:'subFunctionNotSupportedInActiveSession/激活会话不支持该子服务, 当前会话模式下ECU不支持请求的子服务',
    0x7F:'serviceNotSupportedInActiveSession/激活会话不支持该服务, 当前会话模式下ECU不支持请求的服务',
    0x92:'voltageTooHigh/电压过高, 当前电压值超过了编程允许的最大门限值',
    0x93:'voltageTooLow/电压过低, 当前电压值低于了编程允许的最小门限值'
}

def extended_session_activate(client: DoIPConnection) -> bool:
    """
    进入扩展会话
    """
    res = client.send(0x1003)
    if res[0] == 0x50:
        print('[info] Extended session(0x03) activated successfully')
        return True
    else:
        print(f'[info] Extended session(0x03) activated failed: {res.hex()} {NRC[res[-1]]}')
        return False

def compute_key(seed, pincode):
    """
    27密钥计算
    """
    if type(pincode) == type('a'):
        pincodes = bytes.fromhex(pincode)
    else :
        pincodes = pincode
    s1 = pincodes[0]
    s2 = pincodes[1]
    s3 = pincodes[2]
    s4 = pincodes[3]
    s5 = pincodes[4]
    seed_int = int.from_bytes(seed,'big')
    
    or_ed_seed = ((seed_int & 0xFF0000) >> 16) | (seed_int & 0xFF00) | (s1 << 24) | (seed_int & 0xff) << 16

    
    mucked_value = 0xc541a9
    
    for i in range(0,32):
        a_bit = ((or_ed_seed >> i) & 1 ^ mucked_value & 1) << 23
        v9 = v10 = v8 = a_bit | (mucked_value >> 1)
        mucked_value = v10 & 0xEF6FD7 | ((((v9 & 0x100000) >> 20) ^ ((v8 & 0x800000) >> 23)) << 20) | (((((mucked_value >> 1) & 0x8000) >> 15) ^ ((v8 & 0x800000) >> 23)) << 15) | (((((mucked_value >> 1) & 0x1000) >> 12) ^ ((v8 & 0x800000) >> 23)) << 12) | 32 * ((((mucked_value >> 1) & 0x20) >> 5) ^ ((v8 & 0x800000) >> 23)) | 8 * ((((mucked_value >> 1) & 8) >> 3) ^ ((v8 & 0x800000) >> 23))

    
    for j in range(0,32):
        v11 = ((((s5 << 24) | (s4 << 16) | s2 | (s3 << 8)) >> j) & 1 ^ mucked_value & 1) << 23
        v12 = v11 | (mucked_value >> 1)
        v13 = v11 | (mucked_value >> 1)
        v14 = v11 | (mucked_value >> 1)
        mucked_value = v14 & 0xEF6FD7 | ((((v13 & 0x100000) >> 20) ^ ((v12 & 0x800000) >> 23)) << 20) | (((((mucked_value >> 1) & 0x8000) >> 15) ^ ((v12 & 0x800000) >> 23)) << 15) | (((((mucked_value >> 1) & 0x1000) >> 12) ^ ((v12 & 0x800000) >> 23)) << 12) | 32 * ((((mucked_value >> 1) & 0x20) >> 5) ^ ((v12 & 0x800000) >> 23)) | 8 * ((((mucked_value >> 1) & 8) >> 3) ^ ((v12 & 0x800000) >> 23))

    key = ((mucked_value & 0xF0000) >> 16) | 16 * (mucked_value & 0xF) | ((((mucked_value & 0xF00000) >> 20) | ((mucked_value & 0xF000) >> 8)) << 8) | ((mucked_value & 0xFF0) >> 4 << 16)
    return key.to_bytes(3, 'big')

def scan_10service(client: DoIPConnection) -> list[str]:
    SERVICE_ID = 0x10
    result = []
    for sub in range(1, 0x80):
        try: 
            payload = struct.pack('>BB', SERVICE_ID, sub)
            res = client.send(payload)
            print(f'\r[info] Send diagnostic request(0x{SERVICE_ID:x}), payload: {payload.hex()}', end="")
            if res[0] == SERVICE_ID + 0x40:
                print(f'\n[info] Received positive response: {res.hex()}')
                result.append(payload)
            time.sleep(0.1)
        except Exception as e:
            print(f'\n[error] Something error: {e}')
    print(f'\n[info] Found the services of 0x{SERVICE_ID:x}: {[i.hex() for i in result]}')
    result = [i.hex() for i in result]
    return result

def scan_22service(client: DoIPConnection) -> list[str]:
    SERVICE_ID = 0x22
    result = []
    for did in range(0, 0xFFFF + 1):
        try:
            payload = struct.pack('>BH', SERVICE_ID, did)
            res = client.send(payload)
            print(f'\r[info] Send diagnostic request(0x{SERVICE_ID:x}), payload: {payload.hex()}', end="")
            if res[0] == SERVICE_ID + 0x40:
                print(f'\n[info] Received positive response: {res.hex()}')
                result.append(payload)
            time.sleep(0.1)
        except Exception as e:
            print(f'\n[error] Something error: {e}')
    result = [i.hex() for i in result]
    return result

def scan_27service(client: DoIPConnection) -> list[str]:
    SERVICE_ID = 0x27
    result = []
    if not extended_session_activate(client):
        return
    for sub in range(1, 0x80):
        try:
            payload = struct.pack('>BB', SERVICE_ID, sub)
            res = client.send(payload)
            print(f'\r[info] Send diagnostic request(0x{SERVICE_ID:x}), payload: {payload.hex()}', end="")
            if res[0] == SERVICE_ID + 0x40:
                print(f'\n[info] Received positive response: {res.hex()}')
                result.append(payload)
            time.sleep(0.1)
        except Exception as e:
            print(f'\n[error] Something error: {e}')
    print(f'\n[info] Found the services of 0x{SERVICE_ID:x}: {[i.hex() for i in result]}')
    result = [i.hex() for i in result]
    return result


def scan_2Eservice(client: DoIPConnection) -> list[str]:
    SERVICE_ID = 0x2E
    result = []
    if not extended_session_activate(client):
        return
    for did in range(0, 0xFFFF + 1):
        try:
            payload = struct.pack('>BH', SERVICE_ID, did)
            payload += bytes.fromhex('FFFFFFFFFF')
            res = client.send(payload)
            print(f'\r[info] Send diagnostic request(0x{SERVICE_ID:x}), payload: {payload.hex()}', end="")
            if res[0] == SERVICE_ID + 0x40:
                print(f'\n[info] Received positive response: {res.hex()}')
                result.append(payload)
            time.sleep(0.1)
        except Exception as e:
            print(f'\n[error] Something error: {e}')
    print(f'\n[info] Found the services of 0x{SERVICE_ID:x}: {[i.hex() for i in result]}')
    result = [i.hex() for i in result]
    return result

def scan_2Fservice(client: DoIPConnection) -> list[str]:
    SERVICE_ID = 0x2F
    result = []
    if not extended_session_activate():
        return
    for did in range(0, 0xFFFF + 1):
        try:
            payload = struct.pack('>BH', SERVICE_ID, did)
            payload += bytes.fromhex('01')
            res = client.send(payload)
            print(f'\r[info] Send diagnostic request(0x{SERVICE_ID:x}), payload: {payload.hex()}', end="")
            if res[0] == SERVICE_ID + 0x40:
                print(f'\n[info] Received positive response: {res.hex()}')
                result.append(payload)
            time.sleep(0.1)
        except Exception as e:
            print(f'\n[error] Something error: {e}')
    print(f'\n[info] Found the services of 0x{SERVICE_ID:x}: {[i.hex() for i in result]}')
    result = [i.hex() for i in result]
    return result

def scan_31service(client: DoIPConnection) -> list[str]:
    SERVICE_ID = 0x31
    result = []
    if not extended_session_activate(client):
        return
    for did in range(0, 0xFFFF + 1):
        try:
            payload = struct.pack('>BBH', SERVICE_ID, 0x01, did)
            payload += bytes.fromhex('01')
            res = client.send(payload)
            print(f'\r[info] Send diagnostic request(0x{SERVICE_ID:x}), payload: {payload.hex()}', end="")
            if res[0] == SERVICE_ID + 0x40:
                print(f'\n[info] Received positive response: {res.hex()}')
                result.append(payload)
            time.sleep(0.1)
        except Exception as e:
            print(f'\n[error] Something error: {e}')
    print(f'\n[info] Found the services of 0x{SERVICE_ID:x}: {[i.hex() for i in result]}')
    result = [i.hex() for i in result]
    return result

def scan_34service(client: DoIPConnection, compress_method=0x0, encrypt_method=0x0, memory_size=0x4, memory_address=0x4) -> str:
    SERVICE_ID = 0x31
    result = []
    dfi = (compress_method << 4) | encrypt_method
    adfi = (memory_size << 4) | memory_size
    payload = struct.pack('>BBB', SERVICE_ID, dfi, adfi)
    if not extended_session_activate(client):
        return
    res = client.send(payload)
    print(f'[info] Send diagnostic request(0x{SERVICE_ID:x}), payload: {payload.hex()}')
    if res[0] == SERVICE_ID + 0x40:
        print(f'\n[info] Received positive response: {res.hex()}')
        time.sleep(0.1)
        return payload.hex()

def scan_ecus(client: DoIPConnection, start=1, end=0xFFFF) -> list[int]:
    ecu_list = []
    for ecu in range(start, end + 1):
        try:
            payload = struct.pack('>H', 0x1001)
            res = client.send_diagnostic(payload)
            print(f'\r[info] Send default seesion request to: 0x{ecu:x}', end="")
            if res[0] == 0x50:
                print(f'\n[info] Found active ecu: 0x{ecu:x}')
                ecu_list.append(ecu)
            time.sleep(0.1)
        except Exception:
            time.sleep(0.1)
            continue
    ecu_list = [f'0x{i:x}' for i in ecu_list]
    print(ecu_list)
    return ecu_list

# 27服务解锁
def unlock_27service(client: DoIPConnection, pincode: str, session: int = 0x1003, mode: int = 0x19):
    """
    Example:
    ecu_address: 0x1201
    session: 0x1003
    mode: 0x19
    pincode: 'D9AE609FA4'
    """
    res = client.send(session)
    if res[0] == 0x50:
        print(f'[info] Session({session:02x}) activate successfully')
    else:
        print(f'[info] Session({session:02x}) activate failed: {res.hex()} {NRC[res[-1]]}')
        return
    seed_cmd = struct.pack('>BB', 0x27, mode)
    seed_res = client.send(seed_cmd)
    if seed_res[0] == 0x67:
        seed = seed_res[2:]
        print(f'[info] Seed request successful: {seed.hex()}')
        key = compute_key(seed, pincode)
        key_cmd = struct.pack('>BB', 0x27, mode+1) + key
        key_res = client.send(key_cmd)
        if (key_res[0] == 0x67):
            print(f'[info] Service 27 {mode:02x} unlock: success')
        else:
            print(f'[error] Unlock failed: {NRC[key_res[-1]]}')
    else:
        print(f'[error] Request seed failed: {NRC[seed_res[-1]]}')