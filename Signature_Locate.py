import os
import sys
import subprocess
import inject

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

# signature info
signature_info = []

shellcode = b""
backup_shellcode = b""
def xor_decrypt(data):
    return bytes(byte ^ enc_key for byte in data)

def anti_virus_search():
    global kaspersky
    try:
        process = subprocess.Popen("cmd /C where avp.com", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if process.returncode != 0:
            print(f"Command stderr: {stderr} ")
            exit(1)
        else:
            kaspersky = stdout[:-2].decode('utf-8')
    except Exception as e:
        return f"Error while executing command: {str(e)}"
    
def iterate_process(start, end):
    pid = []
    pos = 0
    pre_pos = -1
    i = 0
    print(f'--------------------------------------------')
    print(f'iterate_process, start position: {start}, end position: {end}')
    if SIGNATURE_CHUNCK * INJECT_NUM <= end - start:
        chunk_size = (end - start) // INJECT_NUM
    else:
        chunk_size = SIGNATURE_CHUNCK

    while True:
        i += 1
        pos = min(start + i * chunk_size, end)
        pid.append([inject_shellcode(shellcode[: pos]), pos])
        if pos == end:
            break

    scan()

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
    
    print(f'chunk size: {chunk_size}, pre_pos: {pre_pos}, pos: {pos}')
    if pre_pos == -1:
        print(f'something is wrong, current work space: {start}, pre_pos: {end}')
        exit(1)

    if chunk_size == SIGNATURE_CHUNCK:
        locate(pre_pos, pos)
        
    else:
        iterate_process(pre_pos, pos)


def locate(start, end):
    global signature_info
    global shellcode
    head_inject_pid = {}
    head_pos = 0
    tail_pos = 0
    # inject_pid = pos : pid
    for i in range(start, end+1, STEP):
            head_inject_pid[i] = inject_shellcode(shellcode[0: i])
    if (end - start % STEP) != 0:
            head_inject_pid[end] = inject_shellcode(shellcode[0: end])
            
    scan()

    print(f'head scan, start position: {start}')
    for pos, pid in head_inject_pid.items():
        if inject.is_pid_running(pid) == False:
            if tail_pos == 0:
                tail_pos = pos
                print(f'tail_pos: {tail_pos}')
            # print(f'{pos} is dead')
        else:
            kill_process(pid)
            # print(f'{pos} is alive')


    pid = inject_shellcode(shellcode[tail_pos - SIGNATURE_CHUNCK - STEP: tail_pos])
    scan()
    if inject.is_pid_running(pid) == False:
        print("detect single signature")
        head_pos, tail_pos = single_locate(tail_pos - SINGLE_LONGEST_SIGNATURE - STEP, tail_pos)
    else:
        head_pos = tail_pos - STEP
        kill_process(pid)

    if [head_pos, tail_pos] in signature_info:
        print(f'This range has been ZERO, start: {head_pos}, end: {tail_pos}, maybe file entropy too high')
        exit(1)
    signature_info.append([head_pos, tail_pos])
    shellcode = shellcode[:head_pos] +  b"\x00" * (tail_pos - head_pos) + shellcode[tail_pos:]
    print(f'find signature, ZERO range start: {head_pos}, end: {tail_pos}')
    return 


def single_locate(start, end):
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

    scan()

    print(f'head scan, start position: {start}')
    for pos, pid in head_inject_pid.items():
        if inject.is_pid_running(pid) == False:
            if tail_pos == 0:
                tail_pos = pos
                print(f'tail_pos: {tail_pos}')
            # print(f'{pos} is dead')

        else:
            kill_process(pid)
            # print(f'{pos} is alive')


    print(f'tail scan, start position: {end}')
    for pos, pid in tail_inject_pid.items():
        if inject.is_pid_running(pid) == False:
            if head_pos == 0:
                head_pos = pos
                print(f'head_pos: {head_pos}')
            # print(f'{pos} is dead')

        else:
            kill_process(pid)
            # print(f'{pos} is alive')

    if head_pos > tail_pos:
        print(f'there has multiple singles signature in {start} - {end}')
        return tail_pos, head_pos
    
    return head_pos, tail_pos


def scan():
    try:
        subprocess.run(["cmd", "/C", kaspersky, "SCAN", "/MEMORY", "/i1"], capture_output=True)
        # print('Finish scan')
    except Exception as e:
        return f"Error while executing command: {str(e)}"


def inject_shellcode(code):
    success, injected_address, injected_pid = inject.inject_shellcode(code)
    if success != True:
        print("Error: Failed to inject shellcode")
        exit(1)
    return injected_pid


def kill_process(pid):
    try:
        os.kill(pid, 9)  # Send SIGKILL to terminate the process
    except Exception as e:
        print(f"Failed to terminate process {pid}: {e}")


def main():
    global shellcode
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
    
    pid = inject_shellcode(shellcode)
    scan()
    while inject.is_pid_running(pid) != True:
        length = len(shellcode)
        iterate_process(0, length)
        pid = inject_shellcode(shellcode)
        scan()
    
    kill_process(pid)
    # Write the shellcode to a local file
    output_file = "output_shellcode.bin"
    shellcode = xor_decrypt(shellcode)
    try:
        with open(output_file, "wb") as f:
            f.write(shellcode)
        print(f"Shellcode written to {output_file}, decryption key: {enc_key}")
    except Exception as e:
        print(f"Failed to write shellcode to file: {e}")
    print("Signature locate finished, result:")
    print(signature_info)
    
if __name__ == "__main__":
    main()
    