# Interactive Root Broker

This directory turns the existing one-command DirtyCOW + `flash_recovery` root primitive into a practical interactive root shell for the SM-T377A.

## What changed

The original broker design tried to spawn a second-stage shell binary such as `/system/bin/sh` from a `fork()`/`execve()` inside the broker. Live validation on this device showed that second-stage `execve()` from the broker child is restricted and returns `Permission denied`.

Instead of relying on a limited built-in mini shell, the architecture now uses a **sibling real-shell relay**:
- The initial `install-recovery.sh` payload starts a real `/system/bin/sh -i` shell attached to FIFOs.
- It then launches the `root_pty_broker` relay without using `fork()` or `execve()`.
- The broker simply relays bytes between the host socket and the true shell FIFOs.

This provides a full, unconstrained root shell with pipes, redirection, and script execution, completely bypassing the `execve()` restriction.

## Files

- `root_pty_broker.c` — root broker service process; now runs in FIFO relay mode to bridge the TCP socket to the sibling shell.
- `root_mini_shell.c` — line-oriented builtin shell logic (kept for legacy/diagnostic use).
- `exec_matrix_probe.c` — diagnostic helper used to confirm second-stage exec restrictions (obsolete with relay architecture but kept for reference).
- `root_pty_shell.py` — host-side installer, status helper, stop helper, and interactive client.

## Build

From `C:\InfoSec\android-redteam\work\current\interactive_root`:

```bat
..\..\..\qemu\build-arm.bat root_mini_shell.c root_mini_shell
..\..\..\qemu\build-arm.bat root_pty_broker.c root_pty_broker
```

Optional diagnostic build:

```bat
..\..\..\qemu\build-arm.bat exec_matrix_probe.c exec_matrix_probe
```

The build helper pushes the binaries to `/data/local/tmp/` automatically if `adb` is connected.

## The command you actually want

From `C:\InfoSec\android-redteam\work\current\interactive_root`:

```bat
python root_pty_shell.py shell --restart --reinstall
```

That command:

1. pushes `root_pty_broker`
2. pushes `root_mini_shell` for diagnostics
3. DirtyCOW-overwrites `/system/bin/install-recovery.sh` with the exact-size launcher payload
4. starts `flash_recovery`
5. The payload starts `/system/bin/sh -i` tied to FIFOs, then `exec`s the broker
6. Client forwards a localhost TCP port to `/data/local/tmp/root_pty_broker.sock`
7. Client connects you to the real root shell via the broker relay

You now have a true interactive root shell.

While connected, the host client also intercepts these local helper commands:

- `runroot <cmd>`
- `oneshot <cmd>`

Because of the real shell context, you rarely need these unless you want to intentionally bounce the broker for a standalone `runroot` execution.

If the broker is already installed for the current boot, a plain:

```bat
python root_pty_shell.py shell
```

usually works too.

## Typical workflow

Check status first:

```bat
python root_pty_shell.py status
```

Install the payload without connecting:

```bat
python root_pty_shell.py install
```

Connect to the shell:

```bat
python root_pty_shell.py shell --restart --reinstall
```

Run a one-shot root command without opening the interactive shell:

```bat
python root_pty_shell.py runroot --cwd /data/local/tmp /data/local/tmp/exec_matrix_probe
```

Detach without stopping the broker:

- Press `Ctrl-]`

Stop the broker cleanly afterward:

```bat
python root_pty_shell.py stop
```

## What the shell supports

Because the shell is a full instance of `/system/bin/sh` running as root:

- File redirection (`>`, `<`) and pipes (`|`) work natively.
- Background jobs and standard Android commands (like `toybox`, `toolbox`, `am`, `pm`) are fully accessible.
- Environment variables and session state persist across your interactive session.

This replaces the limited functionality of the older `root_mini_shell`.

## Host-intercepted runroot / oneshot

Type this directly at the interactive shell prompt:

```text
root@gteslteatt:/ # runroot /data/local/tmp/your_binary arg1 arg2
```

The client will:

1. close the current broker session
2. stop `flash_recovery`
3. DirtyCOW-install a one-shot payload
4. run your command as root from the current shell working directory
5. print the command output and exit code
6. reinstall the broker payload
7. reconnect you to a fresh shell session

Notes:

- this is best for short commands and short-lived binaries that you explicitly want to run outside the continuous interactive shell
- current working directory is preserved across the reconnect by the client
- shell environment variables are **not** preserved across the reconnect

## Example session

```text
root@gteslteatt:/ # id
uid=0(root) gid=0(root) groups=0(root) context=u:r:install_recovery:s0
root@gteslteatt:/ # cd /data/local/tmp
root@gteslteatt:/data/local/tmp # ls -la | grep "broker"
-rwxr-xr-x shell    shell      731056 2026-07-10 23:57 root_pty_broker
srw-rw-rw- root     root              2026-07-10 23:57 root_pty_broker.sock
root@gteslteatt:/data/local/tmp # cat /proc/cmdline
root@gteslteatt:/data/local/tmp # exit
```

## Constraints

- This remains a **same-boot** technique. After reboot, rerun `install` or just use `shell --restart --reinstall`.
- This is `install_recovery`-domain root, not `adb root` and not a persistent `su`.
- The payload must remain exactly `1829` bytes because `/system/bin/install-recovery.sh` is that size on this device.
- `flash_recovery` stays occupied while the broker is running, so stop it cleanly when finished.

## Recovery

If the client disconnects or the broker gets wedged:

```bat
python root_pty_shell.py stop
adb forward --remove tcp:61337
python root_pty_shell.py shell --restart --reinstall
```

If the device rebooted, rerun install or use the full shell command with `--reinstall`.

## Diagnostic note

`exec_matrix_probe.c` exists because second-stage child exec was originally the blocker. On this build, a given binary can run as root out of `flash_recovery`, but it cannot reliably `execve()` arbitrary follow-on binaries. The new "sibling shell + FIFO relay" model is the ultimate workaround that keeps the session deeply interactive, effectively bypassing the second-stage Android shell execution restrictions of the kernel.

# NEW NEWS
Compiling a su binary (su.c -> su) and mounting a tmpfs under the root_pty_shell allowed me to execute the su binary from /dev/su-root/su from an adb shell. Massive success. To repro: run the .sh as root_pty_shell and then jump on adb shell and run /dev/su-root/su. Boom boom bam.
