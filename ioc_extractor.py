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

def phase1(file_path, args, output_folder):

    # Load tools to run from config file
    tools_to_run = []
    available_tools = [
        func for func in globals().keys()
        if callable(globals()[func]) and not func.startswith("__")
    ]

    for tool_name in available_tools:
        if config.getboolean('Phase1', tool_name, fallback=False):
            tools_to_run.append(tool_name)

    results = {}
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
    return results

# -------------------------
# Phase 2: Dynamic Analysis
# -------------------------
# def run_cape(plugin, memdump_path, pid=None, extra_args=None):
#     cmd = ["./vol.py", "-f", memdump_path, plugin]
#     if pid:
#         cmd += ["--pid", str(pid)]
#     if extra_args:
#         cmd += extra_args  # Only add if not None
#     print(f"Executing command: {' '.join(cmd)}")  # Debugging info
#     result = subprocess.run(cmd, capture_output=True, text=True)
#     return result.stdout

def phase2(file_path):
    print("Phase 2: Dynamic Analysis is not implemented yet.")
    
    poetry_python = subprocess.run("poetry --directory /opt/CAPEv2/ env list --full-path", shell=True, capture_output=True, text=True).stdout.strip()
    command = f"{poetry_python}/bin/python /opt/CAPEv2/utils/submit.py --timeout 60 {file_path}"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    task_id = int(re.search(r'ID (\d+)', result.stdout).group(1))
    report_path = f"/opt/CAPEv2/storage/analyses/{task_id}/reports/report.json"
    start_time = time.time()
    timeout = 120
    interval = 5
    while not os.path.exists(report_path):
        if time.time() - start_time > timeout:
            raise TimeoutError(f"report.json not found within {timeout} seconds.")
        print(f"Waiting for {report_path} to exist...")
        time.sleep(interval)

    with open(report_path, 'r') as file:
        data = json.load(file)

    try:
        behavior = data['behavior']
        print("Behavior object extracted successfully.")
        # return behavior
    except KeyError:
        raise KeyError("'behavior' key not found in the JSON file.")
    
    print(behavior)

# -------------------------
# Phase 3: Memory Forensics
# -------------------------
def run_volatility(plugin, memdump_path, pid=None, extra_args=None):
    cmd = ["tools/volatility3/vol.py", "-f", memdump_path, plugin]
    if pid:
        cmd += ["--pid", str(pid)]
    if extra_args:
        cmd += extra_args  # Only add if not None
    print(f"Executing command: {' '.join(cmd)}")  # Debugging info
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout

# Filtering functions (same as before)
def filter_pslist(output):
    return [line for line in output.splitlines() if re.search(r"(short lifespan|suspicious process)", line, re.IGNORECASE)]

def filter_malfind(output):
    return [line for line in output.splitlines() if re.search(r"(Executable|Injected)", line, re.IGNORECASE)]

def filter_netscan(output):
    return [line for line in output.splitlines() if re.search(r"(foreign|unknown|non-local|185\.234\.219\.55)", line, re.IGNORECASE)]

def filter_cmdline(output):
    return [line for line in output.splitlines() if re.search(r"(base64|EncodedCommand|wscript|powershell|cmd\.exe)", line, re.IGNORECASE)]

def filter_dlllist(output):
    return [line for line in output.splitlines() if re.search(r"(AppData|Temp|unknown|unloaded|unsigned|random\.dll)", line, re.IGNORECASE)]

def filter_handles(output):
    return [line for line in output.splitlines() if re.search(r"(Temp|RunOnce|Run|Registry|HKEY|startup)", line, re.IGNORECASE)]

def filter_filescan(output):
    return [line for line in output.splitlines() if re.search(r"(exe|dll|tmp|scr|sys|bat|ps1|js|hta)", line, re.IGNORECASE)]

def get_descendant_pids(memdump_path):
    try:
        # First, get the PID of 'pyw.exe'
        cmd = ["./vol.py", "-f", memdump_path, "-r", "json", "windows.pslist.PsList"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        pslist_output = result.stdout
        processes = json.loads(pslist_output)
        pyw_pid = None
        for proc in processes:
            if proc.get('ImageFileName', '').lower() == 'pyw.exe':
                pyw_pid = proc.get('PID')
                break
        if pyw_pid is None:
            print("Could not find process with ImageFileName 'pyw.exe'")
            return []

        # Now, get the process tree starting from 'pyw.exe'
        cmd = ["./vol.py", "-f", memdump_path, "-r", "json", "windows.pstree.PsTree", "--pid", str(pyw_pid)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        pstree_output = result.stdout
        pstree = json.loads(pstree_output)
        descendant_pids = []

        def traverse_tree(process):
            # Look for 'pythonw.exe' running 'analyzer.py'
            if process.get('ImageFileName', '').lower() == 'pythonw.exe' and 'analyzer.py' in process.get('Cmd', ''):
                collect_descendant_pids(process)
            else:
                for child in process.get('__children', []):
                    traverse_tree(child)

        def collect_descendant_pids(process):
            for child in process.get('__children', []):
                descendant_pids.append(child.get('PID'))
                collect_descendant_pids(child)

        # Traverse the tree starting from 'pyw.exe'
        for process in pstree:
            traverse_tree(process)

        return descendant_pids
    except Exception as e:
        print(f"Error: {e}")
        return []

def run_plugin(plugin_name, memdump_path, pid=None, extra_args=None, output_folder=None):
    print(f"Running {plugin_name} for PID {pid if pid else 'N/A'}...")
    try:
        args = []
        if pid:
            args.extend(["--pid", str(pid)])
        if extra_args:
            # Adjust extra_args for output folder
            adjusted_args = []
            for arg in extra_args:
                adjusted_arg = arg.replace("{output_folder}", output_folder) if output_folder else arg
                adjusted_args.append(adjusted_arg)
            args.extend(adjusted_args)
        raw_output = run_volatility(plugin_name, memdump_path, None, args)

        # Apply appropriate filter
        if plugin_name == "windows.pslist.PsList":
            filtered_output = filter_pslist(raw_output)
        elif plugin_name == "windows.malfind.Malfind":
            filtered_output = filter_malfind(raw_output)
        elif plugin_name == "windows.netscan.NetScan":
            filtered_output = filter_netscan(raw_output)
        elif plugin_name == "windows.cmdline.CmdLine":
            filtered_output = filter_cmdline(raw_output)
        elif plugin_name == "windows.dlllist.DllList":
            filtered_output = filter_dlllist(raw_output)
        elif plugin_name == "windows.handles.Handles":
            filtered_output = filter_handles(raw_output)
        elif plugin_name == "windows.filescan.FileScan":
            filtered_output = filter_filescan(raw_output)
        else:
            filtered_output = raw_output.splitlines()

        return plugin_name, filtered_output
    except Exception as e:
        return plugin_name, f"Error: {e}"

def phase3(memdump_path, output_folder):
    # Get the descendant PIDs from the parent 'pyw.exe'
    # descendant_pids = get_descendant_pids(memdump_path)
    # if not descendant_pids:
    #     print("No descendant PIDs found.")
    #     return

    # Load plugins to run from config file
    plugins = []
    for plugin_option in config.items('Phase3'):
        plugin_entry = plugin_option[0]
        enabled = config.getboolean('Phase3', plugin_entry, fallback=False)
        if enabled:
            # Parse plugin details
            details = plugin_entry.split(',')
            plugin_name = details[0]
            requires_pid = 'pid' in details
            args_index = details.index('args') + 1 if 'args' in details else None
            extra_args = details[args_index:] if args_index else None
            plugins.append((plugin_name, requires_pid, extra_args))

    print(plugins)
    exit()

    results = []
    with ThreadPoolExecutor() as executor:
        futures = {}
        for plugin in plugins:
            plugin_name, requires_pid, extra_args = plugin
            if requires_pid:
                for pid in descendant_pids:
                    futures[executor.submit(run_plugin, plugin_name, memdump_path, pid, extra_args, output_folder)] = f"{plugin_name}_{pid}"
            else:
                futures[executor.submit(run_plugin, plugin_name, memdump_path, None, extra_args, output_folder)] = plugin_name

        for future in as_completed(futures):
            plugin_name = futures[future]
            try:
                name, output = future.result()
                results.append((name, output))
            except Exception as e:
                results.append((plugin_name, f"Error: {e}"))

    for name, output in results:
        print(f"\n=== {name} ===")
        if isinstance(output, list):
            if output:
                print("\n".join(output))
            else:
                print("No suspicious items found.")
        else:
            print(output)

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
    
    os.makedirs(output_folder, exist_ok=True)

    # If no phases are specified, run all phases
    if not (args.phase1 or args.phase2 or args.phase3):
        args.phase1 = args.phase2 = args.phase3 = True

    # phase1_results = phase2_results = None

    # # Execute Phases 1 and 2 in parallel
    # with ThreadPoolExecutor() as executor:
    #     futures = {}
    #     if args.phase1:
    #         futures[executor.submit(phase1, file_path, args, output_folder)] = 'phase1'
    #     if args.phase2:
    #         futures[executor.submit(phase2, file_path)] = 'phase2'

    #     # Collect results from Phases 1 and 2
    #     for future in as_completed(futures):
    #         phase = futures[future]
    #         try:
    #             if phase == 'phase1':
    #                 phase1_results = future.result()
    #             elif phase == 'phase2':
    #                 phase2_results = future.result()
    #         except Exception as e:
    #             print(f"Error running {phase}: {e}")

    # # Display Phase 1 results
    # if phase1_results:
    #     for tool_name, output in phase1_results.items():
    #         print(f"\n=== {tool_name} ===")
    #         print(output)

    # # Placeholder for Phase 2 results
    # if phase2_results:
    #     print("\n=== Phase 2 Results ===")
    #     print(phase2_results)

    if args.phase1:
        phase1(file_path, args, output_folder)

    if args.phase2:
        phase2(file_path) #, args, output_folder)

    # Run Phase 3 after Phase 2
    if args.phase3:
        if not args.memdump:
            print("Memory dump file is required for Phase 3.")
            sys.exit(1)
        phase3(args.memdump, output_folder)
    
    generate_report()

if __name__ == "__main__":
    main()