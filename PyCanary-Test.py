import os
import time
import sys
import threading
import win32con
import win32file
import argparse
import ctypes

FILE_CREATED = 1
FILE_DELETED = 2
FILE_MODIFIED = 3
FILE_RENAMED_FROM = 4
FILE_RENAMED_TO = 5

check_interval = 1
last_access_times = {}

FILE_LIST_DIRECTORY = 0x0001

def monitor(path_to_watch):
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
                    pop_up(f'[+] Created: {full_filename}')
                elif action == FILE_DELETED:
                    pop_up(f'[-] Deleted: {full_filename}')
                elif action == FILE_MODIFIED:
                    pop_up(f'[+] Modified: {full_filename}')
                elif action == FILE_RENAMED_FROM:
                    pop_up(f'[>] Renamed from {full_filename}')
                elif action == FILE_RENAMED_TO:
                    pop_up(f'[<] Renamed to {full_filename}')
                else:
                    pop_up(f'[?] Unknown action on {full_filename}')
        except Exception:
            pass

def read_paths_from_file(file_path):
    paths_list = []

    with open(file_path, 'r') as file:
        lines = file.readlines()
        paths_list = [line.strip() for line in lines if line.strip()]

    return paths_list


def get_file_access_time(file_path):
    try:
        return os.path.getatime(file_path)
    except FileNotFoundError:
        return None

def pop_up(message):
    ctypes.windll.user32.MessageBoxW(0, message, "PyCanary Alert", 16)

def canary(dir_path):
    while True:
        for root, dirs, files in os.walk(dir_path):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                access_time = get_file_access_time(file_path)
                if file_path in last_access_times:
                    if access_time and access_time > last_access_times[file_path]:
                        pop_up(f"[+] File Accessed!\n[+] File {file_path} was accessed!" )
                last_access_times[file_path] = access_time

        time.sleep(1)

def parse_args():
    parser = argparse.ArgumentParser(prog='PyCanary.exe', description='A Simple CMD Line Canary Token Generator Tool {GitHub:https://github.com/RogueCyberSecurityChannel}')

    parser.add_argument('-pF', '--path-file', dest='path_file', metavar='path_file', type=str,
                        help='Path filename')

    parser.set_defaults(path_file=False)

    args = parser.parse_args(sys.argv[1:])

    arg_errors = arg_error_check(args)

    if len(arg_errors) > 0:
        for error in arg_errors:
            print("  [-] {0}".format(error))
            print()
        parser.print_help()
        sys.exit(1)

    return args

def arg_error_check(args):
    arg_errors = []
    return arg_errors

def main():
    args = parse_args()

    if args.path_file:
        paths = read_paths_from_file(args.path_file)
        for path in paths:
            canary_thread = threading.Thread(target=canary, args=(path,))
            monitor_thread = threading.Thread(target=monitor, args=(path,))
            monitor_thread.start()
            canary_thread.start()

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(str(e))
        sys.exit(1)