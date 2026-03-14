# Userland Attack Matrix

## Still Live

| Surface | Status | Why it still matters |
| ------- | ------ | ------------------- |
| `ABTPersistenceService` | High | Multiple methods reach app logic before auth failure; M23 reaches `persistApp()` package-installed checks |
| `execute` | Medium | Clean 2-method inventory service; good for package discovery and target validation |
| `remoteinjection` / `enterprise_policy` | Medium | Still worth controlled typed probing from device-owner context, but not the first focus |

## Low Return Or Mostly Dead

| Surface | Status | Why it was deprioritized |
| ------- | ------ | ------------------------- |
| `com.smartcom.root.APNWidgetRootService` | Low | Name is misleading; current behavior looks like APN widget plumbing, not privileged command execution |
| Broad binder transact fuzzing | Dead end | Too much noise, weak signal, and repeated permission denials without semantic progress |
| Generic shell-side `ctl.start` / abstract socket poking | Dead end | SELinux blocks the interesting paths from `u:r:shell:s0` |
| Wide kernel brute force outside a concrete primitive | Dead end for now | Device has many crashable paths, but no stable escalation primitive has emerged from breadth-first fuzzing |

## Practical Next Moves

1. Keep the APK-side binder work centered on `ABTPersistenceService` and `execute`.
2. Use typed parcels and observed validation branches, not raw method sprays.
3. Treat `MethodSpec` recovery for ABT M13 as a targeted reverse-engineering task, separate from runtime probing.
4. Use `execute` output to pick real installed packages for ABT M10/M23 follow-up.
