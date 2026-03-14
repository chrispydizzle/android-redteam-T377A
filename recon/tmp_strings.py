import re
with open("work/boot_ramdisk/sbin/adbd", "rb") as f:
    data = f.read()
strings = [s.decode() for s in re.findall(rb"[\x20-\x7e]{8,}", data)]
interesting = [s for s in strings if any(kw in s.lower() for kw in ["root", "secure", "debug", "prop", "selinux", "setuid", "capab", "drop", "ro."])]
for s in interesting[:30]:
    print(s)
