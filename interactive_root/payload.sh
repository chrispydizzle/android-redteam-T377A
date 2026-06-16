#!/system/bin/sh

# 1. Ensure /data/local/tmp exists and is writable
mkdir -p /data/local/tmp/rootshell 2>/dev/null || true

# 2. Create a FIFO for stdin/stdout (keeps shell interactive)
mkfifo /data/local/tmp/rootshell_fifo 2>/dev/null || true

# 3. Copy shell to tmpfs (more reliable than /system)
cp /system/bin/sh /data/local/tmp/rootsh 2>/dev/null || true

# 4. Set SELinux permissive explicitly
setenforce 0 2>/dev/null || true

# 5. Spawn detached shell with FIFO redirections
setsid -r sh -i < /data/local/tmp/rootshell_fifo > /data/local/tmp/rootshell_fifo &

# 6. Keep parent alive for a few seconds so you can attach
sleep 3

# 7. Exit cleanly so init doesn't wait for parent
exit 0
