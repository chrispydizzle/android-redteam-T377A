# Interactive Root Broker

This directory turns the existing one-command DirtyCOW + `flash_recovery` root primitive into a practical interactive root shell for the SM-T377A.

## What changed

The original broker design tried to spawn a second-stage shell binary such as `/system/bin/sh` or a copied shell under `/data/local/tmp`. Live validation on this device showed that approach is unreliable:

- broker startup works
- second-stage `execve()` from the broker child is restricted
- copied `sh` only behaved like a partial builtin shell
- copied `toybox` did not provide a usable `sh` applet surface here

So the current broker no longer depends on a second-stage Android shell. Instead, it runs a built-in mini shell inside the broker child process itself and exposes that session over the same forwarded broker socket.

## Files

- `root_pty_broker.c` — root broker service process; now hosts the built-in mini shell for default sessions
- `root_mini_shell.c` — line-oriented builtin shell logic, also kept as a standalone diagnostic binary
- `exec_matrix_probe.c` — diagnostic helper used to confirm second-stage exec restrictions from the broker child
- `root_pty_shell.py` — host-side installer, status helper, stop helper, and interactive client

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
5. forwards a localhost TCP port to `/data/local/tmp/root_pty_broker.sock`
6. connects you to the broker's built-in root mini shell

While connected, the host client also intercepts these local helper commands:

- `runroot <cmd>`
- `oneshot <cmd>`

Those commands temporarily stop the broker, execute `<cmd>` through the original one-shot `flash_recovery` primitive, print the output, then reinstall and reconnect the broker automatically.

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

## What the mini shell supports

Reliable builtins:

- `help`
- `pwd`
- `cd [dir]`
- `ls [path ...]`
- `cat <path ...>`
- `echo [args ...]`
- `id`
- `uname`
- `ps`
- `mount`
- `getenforce`
- `env`
- `set KEY VALUE`
- `unset KEY`
- `clear`
- `exit` / `quit`

External execution command:

- `run CMD [args ...]`

`run` uses `execvp()`, but current live testing on this device returned `Permission denied` for every tested follow-on binary, including:

- `/system/bin/sh`
- `/system/bin/toolbox`
- `/system/bin/toybox`
- `/data/local/tmp/root_mini_shell`
- `/data/local/tmp/exec_matrix_probe`

So the answer today is: **no, there is not a shell flag you need to toggle**. This root context can keep the first-stage broker alive, but it does not currently allow the shell child to execute arbitrary second-stage binaries. Treat the built-in commands as the real usable surface unless we add more functionality directly into the mini shell or into the broker itself.

## Host-intercepted runroot / oneshot

Type this directly at the interactive mini-shell prompt:

```text
root@SM-T377A:/# runroot /data/local/tmp/your_binary arg1 arg2
```

The client will:

1. close the current broker session
2. stop `flash_recovery`
3. DirtyCOW-install a one-shot payload
4. run your command as root from the current shell working directory
5. print the command output and exit code
6. reinstall the broker payload
7. reconnect you to the mini shell

Notes:

- this is best for short commands and short-lived binaries
- current working directory is preserved across the reconnect
- shell environment variables are **not** preserved across the reconnect
- because the broker is restarted, you will see a fresh mini-shell banner after `runroot`

## Example session

```text
root@SM-T377A:/# help
root@SM-T377A:/# id
root@SM-T377A:/# cd /data/local/tmp
root@SM-T377A:/data/local/tmp# ls .
root@SM-T377A:/data/local/tmp# cat /proc/cmdline
root@SM-T377A:/data/local/tmp# exit
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

`exec_matrix_probe.c` exists because second-stage child exec was the blocker. On this build, the broker itself can run as root, but a broker child cannot reliably `execve()` arbitrary follow-on binaries. The built-in mini shell design is the workaround that keeps the session interactive without depending on a second-stage Android shell.
