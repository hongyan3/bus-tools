import itertools
import random
import sys
import time
from sys import stdout
from libs.can.can_interface import CanInterface


ARBITRATION_ID_MIN = 0x0
ARBITRATION_ID_MAX = 0x7FF
ARBITRATION_ID_MAX_EXTENDED = 0x1FFFFFFF
BYTE_MIN = 0x00
BYTE_MAX = 0xFF
MAX_MESSAGE_LENGTH = 0x8
MIN_DATA_LENGTH = 1
MAX_DATA_LENGTH = 8
DEFAULT_SEED_MAX = 2 ** 16


def list_to_hex_str(data, delimiter=""):
    data_string = delimiter.join(["{0:02x}".format(i) for i in data])
    return data_string

def directive_str(arb_id, data):
    data = list_to_hex_str(data, "")
    directive = "{0:03X}#{1}".format(arb_id, data)
    return directive

def parse_directive(directive):
    segments = directive.split("#")
    arb_id = int(segments[0], 16)
    data_str = segments[1]
    data = [int(data_str[i:i + 2], 16) for i in range(0, len(data_str), 2)]
    return arb_id, data


def write_directive_to_file_handle(file_handle, arb_id, data):
    directive = directive_str(arb_id, data)
    file_handle.write("{0}\n".format(directive))
    file_handle.flush()


def set_seed(seed=None):
    if seed is None:
        seed = random.randint(0, DEFAULT_SEED_MAX)
    print("Seed: {0} (0x{0:x})".format(seed))
    random.seed(seed)


def get_random_arb_id(min_id, max_id):
    arb_id = random.randint(min_id, max_id)
    return arb_id


def get_random_data(min_length, max_length):
    data_length = random.randint(min_length, max_length)
    data = []
    for _ in range(data_length):
        data_byte = random.randint(BYTE_MIN, BYTE_MAX)
        data.append(data_byte)
    return data


def apply_fuzzed_data(initial_data, fuzzed_data, bitmap):
    fuzz_index = 0
    fuzzed_data = fuzzed_data[::-1]
    for index in range(0, len(initial_data)):
        if bitmap[index]:
            initial_data[index] = fuzzed_data[fuzz_index]
            fuzz_index += 1
    return initial_data

def replay_from_file(bus: CanInterface, file_name, delay=0.01):
    """
    从日志文件中读取报文并重放
    :param file_name: 日志文件名
    :param delay: 间隔
    :return:
    """
    with open(file_name, "r") as f:
        for line in f:
            line = line[:len(line) - 1]
            arb_id, data = parse_directive(line)
            bus.send(data=data, arb_id=arb_id)
            print('Message replayed: arb_id: {}, data: {}'.format(hex(arb_id), [hex(i) for i in data]))
            time.sleep(delay)
            
def get_arb_ids_set(self, duration):
    arb_ids = set()
    start = time.time()
    with self.__can_bus as bus:
        while True:
            msg = bus.recv(timeout=0.5)
            arb_ids.add(msg.arbitration_id)
            print('\rMessage received: arb_id: {0}'.format(msg.arbitration_id), end="")
            sys.stdout.flush()
            if time.time() - start > duration:
                print()
                break
    arb_ids = list(arb_ids)
    arb_ids.sort()
    arb_ids = [hex(i) for i in arb_ids]
    print(len(arb_ids))
    return arb_ids


def random_fuzz(device: CanInterface, static_arb_id=None, static_data=None, filename=None, min_id=ARBITRATION_ID_MIN,
                max_id=ARBITRATION_ID_MAX, min_data_length=MIN_DATA_LENGTH, max_data_length=MAX_DATA_LENGTH,
                start_index=0, show_status=True, seed=None, delay=0.01):
    """
    随机FUzz
    """
    if static_arb_id is not None and static_data is not None:
        raise ValueError("Both static arbitration ID and static data cannot be set at the same time")
    if not 0 <= min_id < max_id <= ARBITRATION_ID_MAX:
        raise ValueError("Invalid value for min_id and/or max_id")
    if not MIN_DATA_LENGTH <= min_data_length <= max_data_length <= MAX_DATA_LENGTH:
        raise ValueError("Invalid value for min_data_length ({0}) and/or max_data_length ({1})".format(
            min_data_length, max_data_length))
    if static_data is not None and len(static_data) > MAX_DATA_LENGTH:
        raise ValueError("static_data ({0} bytes) must not be more than {1} bytes long".format(
            len(static_data), MAX_DATA_LENGTH))
    if not 0 <= start_index:
        raise ValueError("Invalid start index '{0}', must be 0 or larger".format(start_index))
    # Seed handling
    set_seed(seed)
    arb_id = None
    data = None
    file_logging_enabled = filename is not None
    output_file = None
    try:
        if file_logging_enabled:
            output_file = open(filename, "a")
        with device as bus:
            current_index = 0
            messages_send = 0
            if show_status:
                print("Starting at index {0}\n".format(start_index))
            # Fuzzing logic
            while True:
                # Set arbitration ID
                if static_arb_id is None:
                    arb_id = get_random_arb_id(min_id, max_id)
                else:
                    arb_id = static_arb_id
                if static_data is None:
                    data = get_random_data(min_data_length, max_data_length)
                else:
                    data = static_data
                if current_index < start_index:
                    current_index += 1
                    continue
                if show_status:
                    print("\rMessages send: {0}, index: {1}".format(messages_send, current_index), end="")
                    stdout.flush()
                device.send(data=data, arb_id=arb_id)
                messages_send += 1
                if file_logging_enabled:
                    write_directive_to_file_handle(output_file, arb_id, data)
                time.sleep(delay)
                current_index += 1
    except IOError as e:
        print("ERROR: {0}".format(e))
    finally:
        if output_file is not None:
            output_file.close()


def bruteforce_fuzz(device: CanInterface, arb_id, initial_data, data_bitmap, filename=None, start_index=0, show_progress=True,
                    show_responses=True, delay=0.01):
    """
    暴力枚举
    """
    if not 2 <= len(initial_data) <= 8:
        raise ValueError("Invalid initial data: must be between 2 and 16 nibbles")
    if not len(initial_data) % 2 == 0:
        raise ValueError("Invalid initial data: must have an even length")
    if not len(initial_data) == len(data_bitmap):
        raise ValueError("Initial data ({0}) and data bitmap ({1}) must have the same length".format(
            len(initial_data), len(data_bitmap)))
    number_of_bruteforce = sum(data_bitmap)
    end_index = 256 ** number_of_bruteforce
    if not 0 <= start_index <= end_index:
        raise ValueError("Invalid start index '{0}', current range is [0-{1}]".format(start_index, end_index))
    # Initialize fuzzed nibble generator
    bruteforce_values = range(0xFF + 1)
    fuzz_data = itertools.product(bruteforce_values, repeat=number_of_bruteforce)
    file_logging_enabled = filename is not None
    output_file = None
    output_data = []
    try:
        if file_logging_enabled:
            output_file = open(filename, "a")
        with device as bus:
            if show_progress:
                print("Starting at index {0} of {1}\n".format(start_index, end_index))
            message_count = 0
            # Traverse all outputs from fuzz generator
            for current_fuzzed_data in fuzz_data:
                # Skip handling until start_index is met
                if message_count < start_index:
                    message_count += 1
                    continue
                # Apply fuzzed data
                output_data = apply_fuzzed_data(initial_data, current_fuzzed_data, data_bitmap)
                # Send message
                bus.send(arb_id=arb_id, data=output_data)
                message_count += 1
                if show_progress:
                    print("\rCurrent: {0} Index: {1}".format(list_to_hex_str(output_data, " "), message_count),
                          end="")
                    stdout.flush()
                # Log to file
                if file_logging_enabled:
                    write_directive_to_file_handle(output_file, arb_id, output_data)
                time.sleep(delay)
            if show_progress:
                print()
    finally:
        if output_file is not None:
            output_file.close()
    if show_progress:
        print("Brute force finished")
