#!/usr/bin/env python3
"""
Scan all system packages for exported components with no permission protection.
Focus on services (most exploitable) and receivers with dangerous actions.
"""
import subprocess
import re
import sys

def run(cmd):
    r = subprocess.run(["adb", "shell", cmd], capture_output=True, text=True, timeout=30)
    return r.stdout

def main():
    # Get all system packages
    pkgs_raw = run("pm list packages -s")
    pkgs = [line.strip().replace("package:", "") for line in pkgs_raw.strip().split('\n') if line.strip()]
    print(f"Scanning {len(pkgs)} system packages...")
    
    findings = []
    
    for i, pkg in enumerate(pkgs):
        if i % 50 == 0:
            print(f"  Progress: {i}/{len(pkgs)}...", file=sys.stderr)
        
        # Get package dump (just the manifest parts)
        try:
            dump = run(f"dumpsys package {pkg}")
        except:
            continue
        
        # Quick check: skip if no exported components
        if 'exported=true' not in dump.lower():
            continue
        
        # Parse the dump for services and receivers
        lines = dump.split('\n')
        
        in_service = False
        in_receiver = False
        in_activity = False
        component_name = ""
        is_exported = False
        has_permission = False
        uid = ""
        
        # Get UID
        uid_match = re.search(r'userId=(\d+)', dump)
        if uid_match:
            uid = uid_match.group(1)
        
        # Get shared user
        shared_match = re.search(r'sharedUser=\S+\s+(\S+)', dump)
        shared_user = shared_match.group(1) if shared_match else ""
        
        for line in lines:
            stripped = line.strip()
            
            # Detect component sections
            if 'Service{' in stripped:
                in_service = True
                in_receiver = False
                in_activity = False
                component_name = re.search(r'\s(\S+/\S+)', stripped)
                component_name = component_name.group(1) if component_name else stripped
                is_exported = False
                has_permission = False
            elif 'Activity{' in stripped or 'ActivityInfo{' in stripped:
                in_activity = True
                in_service = False
                in_receiver = False
                component_name = re.search(r'\s(\S+/\S+)', stripped)
                component_name = component_name.group(1) if component_name else stripped
                is_exported = False
                has_permission = False
            elif 'Receiver{' in stripped:
                in_receiver = True
                in_service = False
                in_activity = False
                component_name = re.search(r'\s(\S+/\S+)', stripped)
                component_name = component_name.group(1) if component_name else stripped
                is_exported = False
                has_permission = False
            
            if 'exported=true' in stripped.lower():
                is_exported = True
            if 'permission=' in stripped and 'permission=null' not in stripped:
                has_permission = True
            
            # When we hit the next component or end, save if interesting
            if (in_service or in_receiver) and is_exported and not has_permission:
                if 'Service{' in stripped or 'Receiver{' in stripped or 'Activity{' in stripped or stripped.startswith('}'):
                    comp_type = "SERVICE" if in_service else "RECEIVER"
                    if in_activity:
                        comp_type = "ACTIVITY"
                    # Only report if UID is system (1000) or has interesting capabilities
                    if uid in ['1000', '1001', '0'] or 'system' in shared_user.lower():
                        findings.append({
                            'pkg': pkg,
                            'uid': uid,
                            'type': comp_type,
                            'component': component_name,
                            'shared_user': shared_user,
                        })
    
    # Output findings
    print(f"\n{'='*80}")
    print(f"EXPORTED COMPONENTS WITHOUT PERMISSION (system/phone/root UIDs)")
    print(f"{'='*80}")
    
    for f in findings:
        print(f"\n{f['type']:10s} {f['component']}")
        print(f"           pkg={f['pkg']} uid={f['uid']} shared={f['shared_user']}")
    
    print(f"\nTotal findings: {len(findings)}")
    
    # Save to file
    with open("work/exported_noauth_services.txt", "w") as out:
        for f in findings:
            out.write(f"{f['type']}\t{f['component']}\t{f['pkg']}\tuid={f['uid']}\n")

main()
