import os, json, sys, base64, re

TEXT_EXTS = {'.md','.txt','.c','.h','.py','.java','.sh','.bat','.xml','.json','.log',
             '.cfg','.conf','.prop','.rc','.te','.mk','.html','.css','.js','.yaml','.yml',
             '.gitignore','.properties','.dat','.lang'}
MAX_PREVIEW = 500000  # 500KB max per file for embedding
MAX_TOTAL = 100000000  # 100MB total content budget

# ═══════════════════════════════════════════════════
# PII DETECTION PATTERNS
# ═══════════════════════════════════════════════════

PII_PATTERNS = [
    # CRITICAL
    ('IMEI', 'CRITICAL', re.compile(r'IMEI\s*\d{0,2}:?\s*(\d{15})', re.IGNORECASE)),
    ('Email', 'CRITICAL', re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')),
    ('Serial', 'CRITICAL', re.compile(r'SN\(([A-Z0-9]{6,})\)')),
    ('Serial', 'CRITICAL', re.compile(r'(?:serial|Serial)\s*[`\'":]?\s*([0-9a-fA-F]{12,16})\b')),
    # HIGH
    ('WiFi_SSID', 'HIGH', re.compile(r'SSID\s*[:\|]\s*([^\|\n,]{3,40})')),
    ('MAC_Address', 'HIGH', re.compile(r'(?:BSSID|MAC|bssid|mac)[^0-9a-fA-F]*([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})')),
    ('Password', 'HIGH', re.compile(r'(?:password|passwd|pass|credential)\s*[=:]\s*["\']?(\S{3,})', re.IGNORECASE)),
    ('UniqueID', 'HIGH', re.compile(r'UN\(([A-Z0-9]{10,})\)')),
    # MEDIUM
    ('Private_IP', 'MEDIUM', re.compile(r'\b((?:192\.168|10\.\d{1,3})\.\d{1,3}\.\d{1,3})\b')),
    ('Android_ID', 'MEDIUM', re.compile(r'android_id[^0-9a-f]*([0-9a-f]{16})', re.IGNORECASE)),
    ('Device_Code', 'MEDIUM', re.compile(r'PRD\(([A-Z0-9\-]{8,})\)')),
]

# Known false positives to skip
PII_FP_SKIP = {
    'Private_IP': {'192.168.1.86'},  # Kali attack box (documented in STATUS.md)
    'Password': {'android', 'pass:android', 'androiddebugkey'},  # debug keystore, not personal
}

# Files/dirs to skip for PII scanning (source code, not data)
PII_SKIP_DIRS = {'src/', 'qemu/', 'apk/', 'compiled/', 'exynos_src/'}

def mask_value(val, category):
    """Mask PII value for safe display."""
    s = str(val).strip().strip("'\"")
    if len(s) <= 4:
        return s  # too short to be meaningful PII
    if category == 'Email':
        parts = s.split('@')
        return parts[0][:2] + '***@' + parts[1] if len(parts) == 2 else s[:3] + '***'
    if category == 'IMEI':
        return s[:4] + '***' + s[-2:]
    if category in ('Serial', 'UniqueID', 'Android_ID', 'Device_Code'):
        return s[:3] + '***' + s[-2:]
    if category == 'MAC_Address':
        return s[:8] + ':XX:XX:XX'
    if category == 'WiFi_SSID':
        return s[:3] + '***' if len(s) > 4 else '***'
    if category == 'Private_IP':
        parts = s.split('.')
        return f"{parts[0]}.{parts[1]}.x.x" if len(parts) == 4 else s[:4] + '***'
    if category == 'Password':
        return '***REDACTED***'
    return s[:3] + '***'

def scan_pii(contents, real_name=None):
    """Scan all file contents for PII. Returns {filepath: [hits]}."""
    pii_results = {}
    
    # Add real name pattern dynamically if found
    name_patterns = []
    if real_name:
        name_patterns.append(('Real_Name', 'CRITICAL', re.compile(re.escape(real_name), re.IGNORECASE)))
        # Also match parts of the name (first + last)
        parts = real_name.split()
        if len(parts) >= 2:
            first, last = parts[0], parts[-1]
            if len(first) > 2 and len(last) > 2:
                name_patterns.append(('Real_Name', 'CRITICAL', re.compile(
                    rf'\b{re.escape(first)}\b.*\b{re.escape(last)}\b', re.IGNORECASE)))
    
    all_patterns = name_patterns + PII_PATTERNS
    
    for filepath, content in contents.items():
        # Skip source code directories
        if any(filepath.startswith(skip) for skip in PII_SKIP_DIRS):
            continue
        
        hits = []
        lines = content.split('\n')
        for lineno, line in enumerate(lines, 1):
            for category, severity, pattern in all_patterns:
                for match in pattern.finditer(line):
                    value = match.group(1) if match.lastindex else match.group(0)
                    
                    # Skip known false positives
                    fps = PII_FP_SKIP.get(category, set())
                    if value.strip().strip("'\"") in fps:
                        continue
                    
                    # Skip if it looks like code (variable assignment in .c/.py/.java)
                    if filepath.endswith(('.c', '.h', '.py', '.java')) and category == 'Password':
                        continue
                    
                    hits.append({
                        'line': lineno,
                        'col': match.start(),
                        'cat': category,
                        'sev': severity,
                        'masked': mask_value(value, category),
                        'ctx': line.strip()[:120],
                    })
        
        if hits:
            pii_results[filepath] = hits
    
    return pii_results

def longpath(p):
    """Handle Windows long paths."""
    ap = os.path.abspath(p)
    if sys.platform == 'win32' and not ap.startswith('\\\\?\\'):
        return '\\\\?\\' + ap
    return ap

def scan_dir(path, rel='', depth=0, max_depth=6):
    entries = []
    try:
        items = sorted(os.listdir(longpath(path)), key=lambda x: (not os.path.isdir(os.path.join(path, x)), x.lower()))
    except (PermissionError, OSError):
        return entries
    for name in items:
        if name.startswith('.') and name not in ['.gitignore']:
            continue
        full = os.path.join(path, name)
        relpath = (rel + '/' + name) if rel else name
        try:
            is_dir = os.path.isdir(longpath(full))
        except OSError:
            continue
        if is_dir:
            skip_dirs = {'__pycache__','node_modules','.git','.github','compiled',
                        'android_kernel_samsung_exynos3475', 
                        'android_prebuilts_gcc_linux-x86_arm_arm-eabi-4.8',
                        'android_vendor_samsung','android_device_samsung_exynos3475-common',
                        'android_device_samsung_j2lte','android_device_samsung_universal3475-common',
                        'local_manifest','DRParser_ghidra.rep', 'decompile', 'work'}
            
            if name in skip_dirs:
                entries.append({'n':name,'p':relpath,'t':'d','ch':[],'note':'external/large repo'})
                continue
            children = scan_dir(full, relpath, depth+1, max_depth) if depth < max_depth else []
            entries.append({'n':name,'p':relpath,'t':'d','ch':children})
        else:
            try:
                size = os.path.getsize(longpath(full))
            except OSError:
                size = 0
            ext = os.path.splitext(name)[1].lower()
            entries.append({'n':name,'p':relpath,'t':'f','s':size,'e':ext})
    return entries

def collect_contents(tree, base_path, contents, budget):
    """Collect file contents for text files within budget."""
    for entry in tree:
        if budget[0] <= 0:
            break
        if entry['t'] == 'd':
            collect_contents(entry.get('ch', []), base_path, contents, budget)
        elif entry['t'] == 'f':
            ext = entry.get('e', '')
            size = entry.get('s', 0)
            # Include text files under MAX_PREVIEW
            if (ext in TEXT_EXTS or entry['n'] in {'.gitignore','Makefile','Kconfig'}) and size <= MAX_PREVIEW and size > 0:
                full = os.path.join(base_path, entry['p'].replace('/', os.sep))
                try:
                    with open(longpath(full), 'r', encoding='utf-8', errors='replace') as f:
                        content = f.read()
                    contents[entry['p']] = content
                    budget[0] -= len(content)
                except:
                    pass

if  __name__ == '__main__':
    
    print("Scanning directory tree...")
    tree = scan_dir('.', '')
    print(f"Tree built: {len(tree)} root entries")

    print("Collecting file contents...")
    contents = {}
    budget = [MAX_TOTAL]
    collect_contents(tree, '.', contents, budget)
    print(f"Collected {len(contents)} files, {MAX_TOTAL - budget[0]:,} bytes")

    # PII scanning — auto-detect real name from UserInfo patterns
    print("Scanning for PII...")
    real_name = None
    for path, content in contents.items():
        m = re.search(r'UserInfo\{\d+:([A-Z][a-z]+ [A-Z]\.? ?[A-Z][a-z]+)', content)
        if m:
            real_name = m.group(1)
            print(f"  Auto-detected name pattern: {real_name[:2]}***")
            break

    pii_results = scan_pii(contents, real_name)
    total_hits = sum(len(v) for v in pii_results.values())
    crit_files = sum(1 for v in pii_results.values() if any(h['sev'] == 'CRITICAL' for h in v))
    print(f"PII scan: {total_hits} hits in {len(pii_results)} files ({crit_files} CRITICAL)")

    # Write tree
    with open('docs/dashboards/_tree.json', 'w', encoding='utf-8') as f:
        json.dump(tree, f, separators=(',',':'))

    # Write contents
    with open('docs/dashboards/_contents.json', 'w', encoding='utf-8') as f:
        json.dump(contents, f, separators=(',',':'))

    # Write PII results
    with open('docs/dashboards/_pii.json', 'w', encoding='utf-8') as f:
        json.dump(pii_results, f, separators=(',',':'))

    print(f"Done. Tree: {os.path.getsize('docs/dashboards/_tree.json'):,} bytes")
    print(f"Contents: {os.path.getsize('docs/dashboards/_contents.json'):,} bytes")
    print(f"PII: {os.path.getsize('docs/dashboards/_pii.json'):,} bytes")
    exit(0)