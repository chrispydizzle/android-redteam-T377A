#!/usr/bin/env python3
"""Analyze SELinux policy for privilege escalation paths."""
import setools

p = setools.SELinuxPolicy('work/sepolicy')

print('=== Domain Transitions FROM shell ===')
for r in p.terules():
    if str(r.ruletype) == 'type_transition':
        if str(r.source) == 'shell':
            print(f'  {r}')

print('\n=== Domain Transitions FROM untrusted_app ===')
for r in p.terules():
    if str(r.ruletype) == 'type_transition':
        if str(r.source) == 'untrusted_app':
            print(f'  {r}')

print('\n=== Permissive Domains ===')
for t in p.types():
    if t.ispermissive:
        print(f'  {t}')

print('\n=== shell allow rules (key permissions) ===')
interesting = ['execute', 'write', 'create', 'setattr', 'unlink', 'ioctl', 'open']
for r in p.terules():
    if str(r.ruletype) == 'allow' and str(r.source) == 'shell':
        perms = set(str(x) for x in r.perms)
        if perms.intersection(interesting):
            print(f'  {r}')

print('\n=== untrusted_app interesting targets ===')
for r in p.terules():
    if str(r.ruletype) == 'allow' and str(r.source) == 'untrusted_app':
        perms = set(str(x) for x in r.perms)
        if perms.intersection(['execute', 'write', 'create', 'ioctl']):
            target = str(r.target)
            if target not in ('untrusted_app', 'app_data_file', 'untrusted_app_devpts',
                            'sdcard_internal', 'sdcard_external', 'fuse', 'tmpfs',
                            'untrusted_app_tmpfs', 'self'):
                print(f'  {r}')

print('\n=== su/root types ===')
for t in p.types():
    name = str(t)
    if 'su' in name.lower() or 'magisk' in name.lower() or 'root' in name.lower():
        print(f'  {t} (permissive={t.ispermissive})')

print('\n=== shell binder access ===')
for r in p.terules():
    if str(r.ruletype) == 'allow' and str(r.source) == 'shell':
        tclass = str(r.tclass)
        if 'binder' in tclass:
            print(f'  {r}')

print('\n=== write to system_file or kernel ===')
for r in p.terules():
    if str(r.ruletype) == 'allow':
        target = str(r.target)
        perms = set(str(x) for x in r.perms)
        if target in ('system_file', 'kernel') and 'write' in perms:
            print(f'  {r}')
