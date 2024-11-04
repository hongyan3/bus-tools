import struct
import time
from doipclient import DoIPClient
from libs.doip.sddb import Sddb
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

DIAG_LOGICAL_ADDRESS = 0x0E80 # ECU Tester address
SCAN_SERVICES = [0x10, 0x11, 0x22, 0x2E]


def write_to_file(file_handle, message):
    file_handle.write('{0}\n'.format(message))
    file_handle.flush()

def print_and_write(file_handle, message):
    print(f'\n{message}')
    file_handle.write('{0}\n'.format(message))
    file_handle.flush()

def dopipConnect(ecu_logical_address) -> DoIPClient:
    address, announcement = DoIPClient.await_vehicle_announcement()
    cdm_logical_address = announcement.logical_address
    cdm_ip, cdm_doip_port = address
    # print("[info] CDM/VGM info: ", cdm_ip, hex(cdm_logical_address), cdm_doip_port)
    # start to connect doip
    client = DoIPClient(cdm_ip, ecu_logical_address, client_logical_address=DIAG_LOGICAL_ADDRESS)
    return client

def getVinCode(doipClient: DoIPClient) -> str:
    vin = doipClient.request_vehicle_identification().vin
    print("[info] vin code: ", vin)

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

def service_27_unlock(ecu_address: int, session: int, subfunction: int, pincode: str) -> bytes:
    """
    27服务解锁
    """
    with dopipConnect(ecu_address) as client:
        session_cmd = struct.pack('>BB', 0x10, session)
        client.send_diagnostic(session_cmd)
        res = client.receive_diagnostic()
        if res[0] == 0x50:
            print(f'[info] Session mode: 0x{session:02x}')
        else:
            print(f'[info] Switch session mode failed: {res.hex()} {NRC[res[-1]]}')
            return
        seed_cmd = struct.pack('>BB', 0x27, subfunction)
        client.send_diagnostic(seed_cmd)
        seed_res = client.receive_diagnostic()
        if (seed_res[0] == 0x67):
            seed = seed_res[2:]
            print(f'[info] Seed request successful: {seed.hex()}')
            key = compute_key(seed, pincode)
            key_cmd = struct.pack('>BB', 0x27, subfunction+1) + key
            client.send_diagnostic(key_cmd)
            key_res = client.receive_diagnostic()
            if (key_res[0] == 0x67):
                print(f'[info] Service 27 0x{subfunction:02x} unlock: success')
            else:
                print(f'[error] Unlock failed: {NRC[key_res[-1]]}')
        else:
            print(f'[error] Request seed failed: {NRC[seed_res[-1]]}')

def hidden_service_discovery(sddb_file, log_file, target_ecu = None, start_index=0):
    """
    隐藏服务扫描
    """
    try:
        output_file = open(log_file, 'a', encoding='utf-8')
        db = Sddb(sddb_file)
        # ecus = db.get_ecus()
        ecus = [0x1601, 0x1692, 0x1693, 0x1695, 0x1670, 0x1675, 0x1701]
        current_index = 0 # 初始化计数器
        for ecu_address in ecus:
            if target_ecu is not None and ecu_address != target_ecu:
                continue
            print(f'[info] start to discovery the ecu: 0x{ecu_address:02x}')
            dids = db.get_dids(ecu_address)
            # services = db.get_services(ecu_address)
            services = SCAN_SERVICES
            doip_client = dopipConnect(ecu_address)
            with doip_client as client:
                for service_id in services:
                    # 计算肯定响应码
                    positive_code = service_id + 0x40
                    print(f'\n[info] start to scan {service_id:02x} service.')
                    command = struct.pack('>B', service_id)
                    subfunctions = db.get_subfunctions(ecu_address, service_id)
                    # 22 服务扫描
                    if service_id == 0x22:
                        for did in range(0x0001, 0xFFFF+1):
                            current_index += 1
                            if current_index < start_index:
                                continue
                            did_command = struct.pack('>H', did)
                            did_command = command + did_command
                            print(f'\r[info] request payload: {ecu_address:02x} {did_command.hex()}, current_index: {current_index}', end="")
                            try:
                                client.send_diagnostic(did_command)
                                res = client.receive_diagnostic()
                                if res[0] == positive_code:
                                    write_to_file(output_file, f'[info] request payload: 0x{ecu_address:02x} {did_command.hex()}, current_index: {current_index}')
                                    print_and_write(output_file, f'[info] received the positive response, payload: {res.hex()}')
                                    if did not in dids:
                                        print_and_write(output_file, f'[success] found the hidden DID: {ecu_address:02x} {service_id:02x}{did:02x}')
                                time.sleep(0.1)
                            except Exception as e:
                                print(f'\n[error] type: {type(e)}, info: {e}')
                                time.sleep(1)

                    # 2E 服务扫描
                    elif service_id == 0x2E:
                        # 进入扩展会话
                        client.send_diagnostic(struct.pack('>H', 0x1003))
                        client.receive_diagnostic()
                        for did in range(0x0001, 0xFFFF+1):
                            current_index += 1
                            if current_index < start_index:
                                continue
                            did_command = struct.pack('>H', did)
                            did_command = command + did_command + struct.pack('>H',0xAAAA)
                            print(f'\r[info] request payload: {ecu_address:02x} {did_command.hex()}, current_index: {current_index}', end="")
                            try:
                                client.send_diagnostic(did_command)
                                res = client.receive_diagnostic()
                                if res[0] == positive_code:
                                    write_to_file(output_file, f'[info] request payload: 0x{ecu_address:02x} {did_command.hex()}, current_index: {current_index}')
                                    print_and_write(output_file, f'[info] received the positive response, payload: {res.hex()}')
                                    print_and_write(output_file, f'[success] found the unauthorized DID: {ecu_address:02x} {service_id:02x}{did:02x}')
                                time.sleep(0.1)
                            except Exception as e:
                                print(f'\n[error] type: {type(e)}, info: {e}')
                                time.sleep(1)
                    elif (ecu_address == 0x34 or ecu_address == 0x35):
                        pass
                    else:
                        for sub_id in range(-1, 0x7F + 1):
                            current_index += 1
                            if current_index < start_index:
                                continue
                            if sub_id == -1:
                                sub_command = command
                            else:
                                sub_command = struct.pack('>B', sub_id)
                                sub_command = command + sub_command
                            print(f'\r[info] request payload: 0x{ecu_address:02x} {sub_command.hex()}, current_index: {current_index}', end="")
                            try:
                                client.send_diagnostic(sub_command)
                                res = client.receive_diagnostic()
                                if res[0] == positive_code:
                                    write_to_file(output_file, f'[info] request payload: 0x{ecu_address:02x} {sub_command.hex()}, current_index: {current_index}')
                                    print_and_write(output_file, f'[info] received the positive response, payload: {res.hex()}')
                                    if sub_id not in subfunctions:
                                        print_and_write(output_file, f'[success] found the hidden subfunction: {ecu_address:02x} {service_id:02x}{sub_id:02x}')
                                time.sleep(0.1)
                            except Exception as e:
                                print(f'\n[error] type: {type(e)}, info: {e}')
                                time.sleep(1) 
    except KeyboardInterrupt:
        print('\n[info] user aborts the program.')      
    finally:
        output_file.close() 



if __name__ == "__main__":
    # hidden_service_discovery(sddb_file=r'D:\workspace\sddb\CX1E_2440_E4-3_DSA_20240229.sddb', log_file='logs/console.log', start_index=0)
    with DoIPConnection(0x1201) as client:
        res = client.send(bytes.fromhex('22f190'))
        print(res.hex())