import os
import time
import sys
import threading
import win32con
import win32file
import win32api
import win32security
import argparse
import ctypes
import subprocess
import wmi
import psutil
import pythoncom
from datetime import datetime

FILE_CREATED = 1
FILE_DELETED = 2
FILE_MODIFIED = 3
FILE_RENAMED_FROM = 4
FILE_RENAMED_TO = 5

last_access_times = {}

FILE_LIST_DIRECTORY = 0x0001

def welcome():
    print(r'''
     ________  ________   _______  ________  ________  ________  ________  ________
    ╱        ╲╱    ╱   ╲╱╱       ╲╱        ╲╱    ╱   ╲╱        ╲╱        ╲╱    ╱   ╲
   ╱         ╱         ╱╱        ╱         ╱         ╱         ╱         ╱         ╱
  ╱╱      __╱╲__      ╱       --╱         ╱         ╱         ╱        _╱╲__      ╱
  ╲╲_____╱     ╲_____╱╲________╱╲___╱____╱╲__╱_____╱╲___╱____╱╲____╱___╱   ╲_____╱

               {GitHub:https://github.com/RogueCyberSecurityChannel}''')

def header(date, year, time):
    header_file = f"""
********************************************************
                      PyCanary Log
  [GitHub:https://github.com/RogueCyberSecurityChannel]

  Date: {date} {year}
  Time: {time}

********************************************************
"""
    return header_file

def running_animation():
    animation = "|/-\\"
    i = 0
    while True:
        sys.stdout.write( "\r" + f" ["  + animation[i % len(animation)] + "] ")
        sys.stdout.flush()
        i += 1
        time.sleep(1)

def readable_time_stamp():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def date_time():
    now = datetime.now()
    month = now.strftime('%B')
    date = now.strftime('%d')
    year = now.strftime('%Y')
    time = now.strftime('%H:%M:%S')

    return month, date, year, time

def log_to_file(message):
    with open('PyCanary_log.csv', 'a') as fd:
        fd.write(f'{message}\r\n')

def read_paths_from_file(file_path):
    paths_list = []

    with open(file_path, 'r') as file:
        lines = file.readlines()
        paths_list = [line.strip() for line in lines if line.strip()]

    return paths_list

def access_time_of_file(file_path):
    try:
        return os.path.getatime(file_path)
    except FileNotFoundError:
        return None

def pop_up(message):
    ctypes.windll.user32.MessageBoxW(0, message, "PyCanary Alert", 16)

def process_monitor():
    date_and_time= date_time()
    date = date_and_time[0] + " " + date_and_time[1]
    year = date_and_time[2]
    time = date_and_time[3]
    header_file = header(date, year, time)
    log_to_file(header_file)
    pythoncom.CoInitialize()
    c = wmi.WMI()
    process_watcher = c.Win32_Process.watch_for('creation')
    while True:
        try:
            new_process = process_watcher()
            cmdline = new_process.CommandLine
            create_date = new_process.CreationDate
            executable = new_process.ExecutablePath
            parent_pid = new_process.ParentProcessId
            pid = new_process.ProcessId
            proc_owner = new_process.GetOwner()

            privileges =  get_process_privileges(pid)
            time_stamp = readable_time_stamp()
            process_log_message =(
                f'Timestamp: [{time_stamp}]\nCmdline: {cmdline}\nCreate Date: {create_date}\nExecutable: {executable}\n'
                f'Parent ID  {parent_pid}\nPid: {pid}\nProc Owner: {proc_owner}\nPrivileges: {privileges}'
            )
            border ="===================================================================================================================================================="
            log_to_file(border)
            log_to_file(process_log_message)
        except wmi.x_wmi as e:
            pass
        except Exception as e:
            print(str(e))
            return

def get_process_privileges(pid):
    try:
        hproc = win32api.OpenProcess(
            win32con.PROCESS_QUERY_INFORMATION, False, pid
            )
        htok = win32security.OpenProcessToken(hproc, win32con.TOKEN_QUERY)
        privs = win32security.GetTokenInformation(
            htok,win32security.TokenPrivileges
            )
        privileges = ''
        for priv_id, flags, in privs:
            if flags == (win32security.SE_PRIVILEGE_ENABLED |
                         win32security.SE_PRIVILEGE_ENABLED_BY_DEFAULT):
                privileges += f' {win32security.LookupPrivilegeName(None, priv_id)} |'
    except Exception:
        privileges = 'N/A'

    return privileges

def get_process_info(pid):
    try:
        process = psutil.Process(pid)
        process_info = {
            'pid': process.pid,
            'name': process.name(),
            'status': process.status(),
            'create_time': process.create_time(),
            'cpu_times': process.cpu_times(),
            'memory_info': process.memory_info(),
            'io_counters': process.io_counters() if process.io_counters() else "N/A",
            'threads': process.num_threads(),
            'open_files': process.open_files(),
            'connections': process.connections(),
            'exe': process.exe(),
            'cmdline': process.cmdline()
        }
        return process_info
    except psutil.NoSuchProcess:
        return f"No process found with PID: {pid}"
    except Exception as e:
        return f"Error retrieving process info: {e}"

def wmic_query():
    try:
        result = subprocess.run(
            ['wmic', 'process', 'get', 'ProcessId,Name,CommandLine'],
            capture_output=True,
            text=True,
            check=True
        )
        raw_output = result.stdout.splitlines()
        processes = []
        for line in raw_output:
            if len(line):
                processes.append(line)
            continue
        return processes
    except subprocess.CalledProcessError:
        print("Error: Unable to retrieve running processes.")
        return
    except Exception:
        return

def extract_pid(processes, filename):
    try:
        search_string = filename
        for line, slice in enumerate(processes):
                for index in range(len(slice) - 1):
                    if slice[index:index + len(search_string)] == search_string:
                            raw_info = processes[line]
                            string_info_list = raw_info.split()
                            raw_pid = string_info_list[-1]
                            if raw_pid:
                                pid = (int(raw_pid))
                                return pid
                            return False
    except Exception:
        return

def win32_api_dir_monitor(path_to_watch):
    h_directory = win32file.CreateFile(
        path_to_watch,
        FILE_LIST_DIRECTORY,
        win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
        None,
        win32con.OPEN_EXISTING,
        win32con.FILE_FLAG_BACKUP_SEMANTICS,
        None
        )
    while True:
        try:
            results = win32file.ReadDirectoryChangesW(
                h_directory,
                1024,
                True,
                win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES |
                win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
                win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
                win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
                win32con.FILE_NOTIFY_CHANGE_SECURITY |
                win32con.FILE_NOTIFY_CHANGE_SIZE,
                None,
                None
            )
            for action, file_name in results:
                full_filename = os.path.join(path_to_watch, file_name)
                if action == FILE_CREATED:
                    pop_up_thread = threading.Thread(target=pop_up,args=(f'[+] File Created: {full_filename}',))
                    pop_up_thread.start()
                    print(f' [+] File created!')
                    print(f' \n [+] File: {full_filename}')
                    pop_up_thread.join()
                elif action == FILE_DELETED:
                    pop_up_thread = threading.Thread(target=pop_up,args=(f'[+] File deleted {full_filename}',))
                    pop_up_thread.start()
                    print(f' [-] File deleted!')
                    print(f' \n [-] File deleted: {full_filename}')
                    pop_up_thread.join()
                elif action == FILE_MODIFIED:
                    pop_up_thread = threading.Thread(target=pop_up,args=(f'[+] File modified\n [+] File: {full_filename}',))
                    pop_up_thread.start()
                    print(f' [*] File modified!')
                    print(f' \n [+] File: {full_filename}')
                    pop_up_thread.join()
                elif action == FILE_RENAMED_FROM:
                    pop_up_thread = threading.Thread(target=pop_up,args=(f'[>] File renamed from {full_filename}',))
                    pop_up_thread.start()
                    print(f' \n [>] File renamed from {full_filename}')
                    pop_up_thread.join()
                elif action == FILE_RENAMED_TO:
                    pop_up_thread = threading.Thread(target=pop_up,args=(f'[<] File renamed to {full_filename}',))
                    pop_up_thread.start()
                    print(f' \n [<] File renamed to {full_filename}')
                    pop_up_thread.join()
                else:
                    pop_up_thread = threading.Thread(target=pop_up,args=(f'[?] Unknown action on {full_filename}',))
                    pop_up_thread.start()
                    print(f' \n [?] Unknown action on {full_filename}')
                    pop_up()
                    pop_up_thread.join()
        except Exception:
            sys.exit(1)

def canary(dir_path):
    try:
        while True:
            for root, dirs, files in os.walk(dir_path):
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    access_time = access_time_of_file(file_path)
                    if file_path in last_access_times:
                        if access_time and access_time > last_access_times[file_path]:
                            time_stamp = readable_time_stamp()
                            index = file_path.rfind('\\')
                            filename = file_path[1 + index:]
                            processes = wmic_query()
                            pid = extract_pid(processes, filename)
                            print(f"\n [!] FILE ACCESSED!\n [*] File: {file_path} was accessed!")
                            if pid != None:
                                process_info = get_process_info(pid)
                                pop_up_thread = threading.Thread(target=pop_up,args=(f"[+] File Accessed!\n[+] File: {file_path} was accessed!",))
                                pop_up_thread.start()
                                print(f' [!] [↓ ↓ ↓ ↓] Access process information [↓ ↓ ↓ ↓]')
                                print(f' [*] Access time: {time_stamp}')
                                print(f' [*] Pid: {process_info["pid"]}')
                                print(f' [*] Process name: {process_info["name"]}')
                                print(f' [*] Status: {process_info["status"]}')
                                cmd_string = ' '.join(process_info['cmdline'])
                                print(f' [*] CMD line: {cmd_string}')
                                print(f' [*] Exe: {process_info["exe"]}')
                                if process_info['connections']:
                                    print(f' [*] Connections: {process_info["connections"]}')
                                print(f' [+] Review "PyCanary_log.csv" for more information')
                                print(f' [!] [↑ ↑ ↑ ↑] Access process information [↑ ↑ ↑ ↑]')
                                pop_up_thread.join()
                            else:
                                pop_up_thread = threading.Thread(target=pop_up,args=(f"[+] File Accessed!\n[+] File: {file_path} was accessed!",))
                                pop_up_thread.start()
                                print(f' [!] Unable to determine access process')
                                print(f' [+] {file_name} was accessed at [{time_stamp}]')
                                print(f' [!] Review "PyCanary_log.csv" for more information')
                                pop_up_thread.join()
                    last_access_times[file_path] = access_time
            time.sleep(1)
    except Exception as e:
        print(str(e))
        sys.exit(1)

def parse_args():
    parser = argparse.ArgumentParser(prog='PyCanary.exe', description='A simple CMD line canary tool for monitoring directories of your choosing {GitHub:https://github.com/RogueCyberSecurityChannel}')

    parser.add_argument('-pF', '--path-file', dest='path_file', metavar='path_file', type=str,
                        help='Directory path file: ')
    parser.set_defaults(path_file=False)

    args = parser.parse_args(sys.argv[1:])
    arg_errors = arg_error_check(args)

    if len(arg_errors) > 0:
        for error in arg_errors:
            print("\n  [-] {0}".format(error))
            print()
        parser.print_help()
        sys.exit(1)

    return args

def arg_error_check(args):
    arg_errors = []
    if args.path_file == False:
        arg_errors.append('Argument error. Example: "PyCanary.exe -pF <dir_paths.txt>"')
    return arg_errors

def main():
    try:
        welcome()
        args = parse_args()
        if args.path_file:
            animation_thread = threading.Thread(target=running_animation, daemon=True)
            process_monitor_thread = threading.Thread(target=process_monitor, daemon=True)
            process_monitor_thread.start()
            print('\n [+] Process monitor started')
            time.sleep(1)
            paths = read_paths_from_file(args.path_file)
            for path in paths:
                canary_thread = threading.Thread(target=canary, args=(path,), daemon=True)
                win32_api_dir_monitor_thread = threading.Thread(target=win32_api_dir_monitor, args=(path,), daemon=True)
                win32_api_dir_monitor_thread.start()
                canary_thread.start()
            animation_thread.start()
        while True:
            time.sleep(0.1)
    except KeyboardInterrupt:
            print("\n")
            sys.exit(0)
    except Exception as e:
        print(str(e))
        sys.exit(1)

if __name__ == '__main__':
    main()
