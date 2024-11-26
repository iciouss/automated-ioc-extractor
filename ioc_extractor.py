#!/usr/bin/env python
import argparse
import subprocess
import os
import sys
import hashlib
import re
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import configparser
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading

config = configparser.ConfigParser()
config.read('tools.ini')

# -------------------------
# Phase 1: Static Analysis
# -------------------------
def run_tool(command, output_file=None, output_folder=None):
    print(f"Executing command: {command}")
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if output_file:
        if output_folder:
            output_path = os.path.join(output_folder, output_file)
            with open(output_path, 'w') as f:
                f.write(result.stdout)
    return result.stdout

def avclass(file_path, output_folder, api_key):
    # Calculate sha256 hash
    sha256_hash = hashlib.sha256()
    with open(file_path,"rb") as f:
        for byte_block in iter(lambda: f.read(4096),b""):
            sha256_hash.update(byte_block)
    sha256 = sha256_hash.hexdigest()
    vt_command = f"curl https://www.virustotal.com/api/v3/files/{sha256} --header 'X-Apikey: {api_key}'"
    run_tool(vt_command, output_file='virustotal_result.txt', output_folder=output_folder)
    av_command = f"avclass -f {output_folder}/virustotal_result.txt"
    output = run_tool(av_command, output_file='avclass_result.txt', output_folder=output_folder)
    return output

def capa(file_path, output_folder):
    command = f"tools/capa -v {file_path}"
    output = run_tool(command, output_file='capa_result.txt', output_folder=output_folder)
    return output

def floss(file_path, output_folder):
    command = f"floss --minimum-length 7 {file_path}"
    output = run_tool(command, output_file='floss_result.txt', output_folder=output_folder)
    return output

def exiftool(file_path, output_folder):
    command = f"exiftool {file_path}"
    output = run_tool(command, output_file='exiftool_result.txt', output_folder=output_folder)
    return output

def file(file_path, output_folder):
    command = f"file {file_path}"
    output = run_tool(command, output_file='file_result.txt', output_folder=output_folder)
    return output

def strings(file_path, output_folder):
    command = f"strings {file_path}"
    output = run_tool(command, output_file='strings_result.txt', output_folder=output_folder)
    return output

def md5sum(file_path, output_folder):
    command = f"md5sum {file_path}"
    output = run_tool(command, output_file='md5sum_result.txt', output_folder=output_folder)
    return output

def sha256sum(file_path, output_folder):
    command = f"sha256sum {file_path}"
    output = run_tool(command, output_file='sha256sum_result.txt', output_folder=output_folder)
    return output

def xxd(file_path, output_folder):
    command = f"xxd {file_path}"
    output = run_tool(command, output_file='xxd_result.txt', output_folder=output_folder)
    return output

def yara(file_path, output_folder):
    command = f"yara yara-rules-full.yar {file_path}"
    output = run_tool(command, output_file='yara_result.txt', output_folder=output_folder)
    return output

def imphash(file_path, output_folder):
    command = f"python -c \"import pefile, sys; print(pefile.PE(sys.argv[1]).get_imphash())\" {file_path}"
    output = run_tool(command, output_file='imphash_result.txt', output_folder=output_folder)
    return output

def rabin2(file_path, output_folder):
    command = f"rabin2 -g {file_path}"
    output = run_tool(command, output_file='rabin2_result.txt', output_folder=output_folder)
    return output

def diec(file_path, output_folder):
    command = f"tools/Detect-It-Easy/docker/diec.sh -e -j {file_path}"
    output = run_tool(command, output_file='diec_result.txt', output_folder=output_folder)
    return output

def ssdeep(file_path, output_folder):
    command = f"ssdeep {file_path}"
    output = run_tool(command, output_file='ssdeep_result.txt', output_folder=output_folder)
    return output

def phase1(file_path, args, output_folder):
    print("Starting static analysis (phase1) ...")
    print("=====================================")

    tools_to_run = []
    available_tools = [
        func for func in globals().keys()
        if callable(globals()[func]) and not func.startswith("__")
    ]

    for tool_name in available_tools:
        if config.getboolean('Phase1', tool_name, fallback=False):
            tools_to_run.append(tool_name)

    results = {}
    output_folder = f"{output_folder}/static"
    os.makedirs(output_folder, exist_ok=True)
    with ThreadPoolExecutor() as executor:
        futures = {}
        for tool_name in tools_to_run:
            if tool_name == 'avclass':
                if not args.vt_api_key:
                    print("avclass: VirusTotal API key is required for VirusTotal analysis.")
                    continue
                futures[executor.submit(avclass, file_path, output_folder, args.vt_api_key)] = tool_name
            else:
                tool_func = globals().get(tool_name)
                if callable(tool_func):
                    futures[executor.submit(tool_func, file_path, output_folder)] = tool_name
                else:
                    print(f"Tool {tool_name} is not defined.")
        for future in as_completed(futures):
            tool_name = futures[future]
            try:
                output = future.result()
                results[tool_name] = output
            except Exception as e:
                results[tool_name] = f"Error: {e}"
    
    print("=====================================")
    print(f"Static analysis completed. Results are available in {output_folder}")
    print("=====================================")
    # return results

# -------------------------
# Phase 2: Dynamic Analysis
# -------------------------
class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    dump_path = None 

    def do_POST(self):
        if not self.dump_path:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b'Server not properly initialized.')
            return
    
        try:
            content_length = int(self.headers['Content-Length'])
            file_data = self.rfile.read(content_length)
            # Check folder and save file
            os.makedirs(os.path.dirname(self.dump_path), exist_ok=True)
            with open(self.dump_path, 'wb') as f:
                f.write(file_data)
            
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'File received')
            self.wfile.flush()
        
        except:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b'Failed to save the file')
            self.wfile.flush()
        
        finally:        
            # Stop the server after handling the request
            if self.stop_server_callback:
                print("Stopping server after receiving the file...")
                self.stop_server_callback()

def start_server(dump_path, port=8888):
    SimpleHTTPRequestHandler.dump_path = dump_path
    server = HTTPServer(('0.0.0.0', port), SimpleHTTPRequestHandler)
    
    # Define a callback to stop the server
    def stop_server(*args):
        server.shutdown()
    
    SimpleHTTPRequestHandler.stop_server_callback = stop_server

   # Run the server in a separate thread
    def server_thread():
        print(f"Server starting on port {port}, dump path: {dump_path}")
        server.serve_forever()

    thread = threading.Thread(target=server_thread, daemon=True)
    thread.start()
    return thread

def phase2(file_path, output_folder):
    print("Starting dynamic analysis (phase2) ...")
    print("======================================")

    # Get poetry executable for running CAPE
    poetry_python = subprocess.run("poetry --directory /opt/CAPEv2/ env list --full-path", shell=True, capture_output=True, text=True).stdout.strip()
    
    # Run CAPE
    command = f"{poetry_python}/bin/python /opt/CAPEv2/utils/submit.py --timeout 60 {file_path}"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    task_id = int(re.search(r'ID (\d+)', result.stdout).group(1))
    report_path = f"/opt/CAPEv2/storage/analyses/{task_id}/reports/report.json"
    dump_path =  f"/opt/CAPEv2/storage/analyses/{task_id}/memory/memdump.raw.zst"

    # Start HTTP server to receive the dump file for phase 3
    server_thread = start_server(dump_path)

    start_time = time.time()
    timeout = 200
    interval = 15
    # Wait for report to be created
    while not os.path.exists(report_path):
        if time.time() - start_time > timeout:
            raise TimeoutError(f"report.json not found within {timeout} seconds.")
        print(f"Waiting for {report_path} to exist...")
        time.sleep(interval)

    # Open report.json file
    with open(report_path, 'r') as file:
        data = json.load(file)

    output_folder = f"{output_folder}/dynamic"
    os.makedirs(output_folder, exist_ok=True)

    try:
        behavior = data['behavior']
        # print("Behavior object extracted successfully.")
        if output_folder:
            output_path = os.path.join(output_folder, "behavior_results.txt")
            with open(output_path, 'w') as f:
                json.dump(behavior, f)
    except Exception as e:
        print(f"Error: {e}")
        return []
    
    if os.path.exists(dump_path):
        print("Memory dump received.")
    else:
        print("Memory dump NOT received.")
        dump_path = None
    
    print("=====================================")
    print(f"Dynamic analysis completed. Results are available in {output_folder}")
    print("=====================================")
    return dump_path

# -------------------------
# Phase 3: Memory Forensics
# -------------------------

def apply_filters(plugin_name, output):
    if plugin_name == "windows.pslist":
        return [line for line in output.splitlines() if re.search(r"(short lifespan|suspicious process)", line, re.IGNORECASE)]
    elif plugin_name == "windows.malfind":
        return [line for line in output.splitlines() if re.search(r"(Executable|Injected)", line, re.IGNORECASE)]
    elif plugin_name == "windows.netscan":
        return [line for line in output.splitlines() if re.search(r"(foreign|unknown|non-local)", line, re.IGNORECASE)]
    elif plugin_name == "windows.cmdline":
        return [line for line in output.splitlines() if re.search(r"(base64|EncodedCommand|wscript|powershell|cmd\.exe)", line, re.IGNORECASE)]
    elif plugin_name == "windows.dlllist":
        return [line for line in output.splitlines() if re.search(r"(AppData|Temp|unknown|unloaded|unsigned|random\.dll)", line, re.IGNORECASE)]
    elif plugin_name == "windows.handles":
        return [line for line in output.splitlines() if re.search(r"(Temp|RunOnce|Run|Registry|HKEY|startup)", line, re.IGNORECASE)]
    elif plugin_name == "windows.filescan":
        return [line for line in output.splitlines() if re.search(r"(exe|dll|tmp|scr|sys|bat|ps1|js|hta)", line, re.IGNORECASE)]
    else:
        return None

def run_volatility(plugin_name, memdump_file, pid=None, extra_args=None, output_folder=None):
    command = f"./tools/volatility3/vol.py -f {memdump_file} {plugin_name}"
    if pid:
        command += f" --pid {pid}"
    if extra_args:
        command += f" {extra_args}"
    print(f"Executing command: {command}")  # Debugging info
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if output_folder:
        raw_output_folder = f"{output_folder}/raw"
        filtered_output_folder = f"{output_folder}/filtered"
        pid = str(pid) if pid else "all"
        os.makedirs(raw_output_folder, exist_ok=True)
        os.makedirs(filtered_output_folder, exist_ok=True)

        raw_output_file = os.path.join(raw_output_folder, f"{plugin_name}.{pid}_results.txt")
        with open(raw_output_file, 'w') as f:
            f.write(result.stdout)

        filtered_output_file = os.path.join(filtered_output_folder, f"{plugin_name}.{pid}_results.txt")
        with open(filtered_output_file, 'w') as f:
            f.write(apply_filters(result.stdout, plugin_name))

def get_pids(memdump_file):
    try:
        # Get PID of pyw.exe (CAPE agent)
        command = f"./tools/volatility3/vol.py -f {memdump_file} -r json windows.pslist.PsList"
        # ["./vol.py", "-f", memdump_path, "-r", "json", "windows.pslist.PsList"]
        print(f"Executing command: {command}")
        pslist_result = subprocess.run(command, capture_output=True, shell=True, text=True)
        processes = json.loads(pslist_result.stdout)
        pyw_pid = None
        for proc in processes:
            if proc.get('ImageFileName', '').lower() == 'pyw.exe':
                pyw_pid = proc.get('PID')
                break
        if pyw_pid is None:
            print("Could not find process 'pyw.exe'")
            return []
        
        # Get process tree of pyw.exe
        command = f"./tools/volatility3/vol.py -f {memdump_file} -r json windows.pstree.PsTree --pid {str(pyw_pid)}"
        pstree_result = subprocess.run(command, capture_output=True, shell=True, text=True)
        pstree = json.loads(pstree_result.stdout)
        
        children_pids = []
        def traverse_tree(process):
            # Search for process pythonw.exe with command analyzer.py
            if process.get('ImageFileName', '').lower() == 'pythonw.exe' and 'analyzer.py' in process.get('Cmd', ''):
                collect_children_pids(process)
            else:
                for child in process.get('__children', []):
                    traverse_tree(child)

        def collect_children_pids(process):
            for child in process.get('__children', []):
                children_pids.append(child.get('PID'))
                collect_children_pids(child)
        
        for process in pstree:
            traverse_tree(process)

        return children_pids
    
    except Exception as e:
        return [], f"Error: {e}"
    
def prepare_dump(memdump_path):
    memdump_dir = os.path.dirname(memdump_path)
    memdump_file = os.path.join(memdump_dir, "memdump.raw")
    command = f"zstdcat {memdump_path} > {memdump_file}"
    subprocess.run(command, capture_output=True, shell=True)
    if os.path.exists(memdump_file):
        print("Memory dump file ready to process.")
        return memdump_file
    else:
        print("Unable to process memory dump.")
        return None

def phase3(memdump_path, args, output_folder):
    print("Starting memory forensics (phase3) ...")
    print("======================================")

    if args.memdump:
        memdump_file = memdump_path
    else:    
        memdump_file = prepare_dump(memdump_path)
        
    pid_list = get_pids(memdump_file)
    if not pid_list:
        print("No valid PIDs found.")
        return
    else: 
        print(f"Running analysis on these PIDs: {pid_list}")

    # Load plugins to run from config file
    plugins = []
    for plugin_option in config.items('Phase3'):
        plugin_entry = plugin_option[0]
        enabled = config.getboolean('Phase3', plugin_entry, fallback=False)
        if enabled:
            # Parse plugin details
            details = plugin_entry.split(',')
            plugin_name = details[0]
            requires_pid = 'use_pid' in details
            args_index = details.index('args') + 1 if 'args' in details else None
            extra_args = ' '.join(details[args_index:]) if args_index else None
            plugins.append((plugin_name, requires_pid, extra_args))

    # print(plugins)

    output_folder = f"{output_folder}/memory"
    os.makedirs(output_folder, exist_ok=True)
    results = []
    with ThreadPoolExecutor() as executor:
        futures = {}
        for plugin in plugins:
            plugin_name, requires_pid, extra_args = plugin
            if requires_pid: 
                for pid in pid_list: # execute plugin for each pid
                    futures[executor.submit(run_volatility, plugin_name, memdump_file, pid, extra_args, output_folder)] = f"{plugin_name}_{pid}"
            else: # execute plugin for whole memdump
                futures[executor.submit(run_volatility, plugin_name, memdump_file, None, extra_args, output_folder)] = plugin_name

        for future in as_completed(futures):
            plugin_name = futures[future]
            try:
                name, output = future.result()
                results.append((name, output))
            except Exception as e:
                results.append((plugin_name, f"Error: {e}"))

    print("=====================================")
    print(f"Memory forensics analysis completed. Results are available in {output_folder}")
    print("=====================================")

def generate_report():
    pass

def main():
    parser = argparse.ArgumentParser(description="Automated Malware Analysis")
    parser.add_argument("-f", "--file", required=True, help="Path to the malware sample file")
    parser.add_argument("-o", "--output-folder", default="output", help="Output folder for result files")
    parser.add_argument("--phase1", action='store_true', help="Run Phase 1: Static Analysis")
    parser.add_argument("--phase2", action='store_true', help="Run Phase 2: Dynamic Analysis")
    parser.add_argument("--phase3", action='store_true', help="Run Phase 3: Memory Forensics")
    parser.add_argument("--vt-api-key", help="API Key for VirusTotal")
    parser.add_argument("--memdump", help="Path to the memory dump file for Phase 3")
    args = parser.parse_args()
    
    file_path = args.file
    output_folder = args.output_folder
    os.makedirs(output_folder, exist_ok=True)

    # If no phases are specified, run all phases
    if not (args.phase1 or args.phase2 or args.phase3):
        args.phase1 = args.phase2 = args.phase3 = True


    if args.phase1:
        phase1(file_path, args, output_folder)

    dump_path = None
    if args.phase2:
        dump_path = phase2(file_path, output_folder) #, args, output_folder)

    # run phase3 after phase2
    if args.phase2 and args.phase3:
        if dump_path:
            phase3(dump_path, args, output_folder)
    # run only phase 3
    else: 
        if args.phase3:
            if not args.memdump:
                print("Memory dump file is required for Phase 3.")
                sys.exit(1)
            phase3(args.memdump, args, output_folder)
    
    generate_report()

if __name__ == "__main__":
    main()