#!/usr/bin/env python3
import subprocess
import sys

def run_command(cmd, timeout=5):
    """Run a shell command and return output"""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "TIMEOUT"
    except Exception as e:
        return -1, "", str(e)

def main():
    print('='*80)
    print('OTP Service Fuzzing - Service Call Codes 1-20')
    print('='*80)
    
    for code in range(1, 21):
        print(f'\n[*] Testing code {code}...')
        cmd = f'adb shell service call OTP {code}'
        returncode, stdout, stderr = run_command(cmd)
        
        print(f'Return code: {returncode}')
        if stdout:
            print(f'STDOUT:\n{stdout}')
        if stderr:
            print(f'STDERR:\n{stderr}')
    
    print('\n' + '='*80)
    print('OTP Service Dumpsys')
    print('='*80 + '\n')
    
    cmd = 'adb shell dumpsys OTP'
    returncode, stdout, stderr = run_command(cmd, timeout=10)
    
    print(f'Return code: {returncode}')
    if stdout:
        print(stdout)
    if stderr:
        print(f'STDERR:\n{stderr}')

if __name__ == '__main__':
    main()
