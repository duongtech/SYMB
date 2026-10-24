import time, os, sys

def main():
    pid = os.getpid()
    print(f"[TARGET_DAEMON] Running with PID: {pid}", flush=True)
    print(f"[TARGET_DAEMON] Memory Address of verify_token flag is being monitored...", flush=True)
    
    # State flag in RAM: 0 = Access Denied, 1 = ACCESS GRANTED
    flag = [0]
    
    iteration = 0
    while iteration < 20:
        iteration += 1
        if flag[0] == 0:
            print(f"[{time.strftime('%H:%M:%S')}] [PID:{pid}] STATUS: ACCESS DENIED - License token mismatch!", flush=True)
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [PID:{pid}] ★ STATUS: ACCESS GRANTED! Zero-disk in-memory hook triggered!", flush=True)
        time.sleep(1)

if __name__ == "__main__":
    main()
