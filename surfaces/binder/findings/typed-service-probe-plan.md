# Typed Service Probe Plan

## Scope

This plan narrows the APK-side binder work to the two userland services that still reach application logic without an immediate authorization gate:

- `ABTPersistenceService` / `com.absolute.android.persistence.IABTPersistence`
- `execute` / `IExecuteManager`

The current probe entrypoint is [work/privesc_apk/src/com/privesc/agent/BinderProbeService.java](c:/InfoSec/android-redteam/work/privesc_apk/src/com/privesc/agent/BinderProbeService.java).

## ABTPersistence

Confirmed `AppProfile` parcelable layout from recon:

```text
i32 1
s16 packageName
i32 version
s16 apkPath
s16 downloadUrl
```

Confirmed method map that reaches real logic before auth rejection:

| Method | Arguments | Observed pre-auth behavior |
| ------ | --------- | -------------------------- |
| M10 | `AppProfile` | Tries to update persist flag, then errors on missing package |
| M13 | `MethodSpec` parcelable | Reflection-style dispatch, exact field layout still unresolved |
| M14 | `String packageName, IABTPing callback` | Reaches null callback check |
| M15 | `String packageName` | Reaches calling-package comparison |
| M16 | `String packageName` | Reaches null-package validation |
| M21 | `String packageName, String accessKey` | Reaches key validation |
| M22 | `String packageName, int version` | Reaches version validation |
| M23 | `AppProfile` | Reaches installed-package check in `persistApp()` |
| M25 | `String packageName, String accessKey` | Reaches key validation |

Recommended test sequence:

1. Run `BinderProbeService` with `target=abt` and `package=com.privesc.agent`.
2. Confirm M10 and M23 both reject on package state, not authorization.
3. Re-run with an actually installed Samsung system package if M23 still only proves package-presence logic.
4. Treat M13 as a separate reverse-engineering task until the `MethodSpec` parcelable is recovered from boot.oat or a matching framework stub.
5. Treat M21 and M25 as access-key discovery surfaces, not immediate exploit paths.

Suggested launch command:

```bat
adb shell am startservice -n com.privesc.agent/.BinderProbeService --es target abt --es package com.privesc.agent
adb shell cat /sdcard/binder_probe.txt
```

Receiver-driven launch path:

```bat
adb shell am broadcast -a com.privesc.agent.COMMAND --es cmd binder_probe --es target abt --es package com.privesc.agent
adb shell cat /sdcard/agent_output.txt
adb shell cat /sdcard/binder_probe.txt
```

## execute

Current evidence says `execute` is much narrower than the name suggests:

| Method | Arguments | Expected behavior |
| ------ | --------- | ----------------- |
| M1 | none | Returns inventory of executable packages with launch metadata |
| M2 | `String packageName` | Returns boolean-ish answer for whether the package is executable/known |

Recommended test sequence:

1. Run `BinderProbeService` with `target=execute`.
2. Confirm M1 returns a stable item count and decodes the first entries consistently.
3. Confirm M2 returns a deterministic `0/1` style result for `com.privesc.agent` and `com.android.settings`.
4. Use the returned app inventory as recon input for later package-targeted abuse, not as an execution primitive by itself.

Suggested launch command:

```bat
adb shell am startservice -n com.privesc.agent/.BinderProbeService --es target execute --es package com.privesc.agent
adb shell cat /sdcard/binder_probe.txt
```

Receiver-driven launch path:

```bat
adb shell am broadcast -a com.privesc.agent.COMMAND --es cmd binder_probe --es target execute --es package com.privesc.agent
adb shell cat /sdcard/agent_output.txt
adb shell cat /sdcard/binder_probe.txt
```

## Notes

- `smartcom` remains in the probe as a legacy comparison path only.
- `ABTPersistenceService` is the better exploitation candidate.
- `execute` is still useful, but mainly for package/launcher inventory and validation.
- The receiver path is safer operationally when you are already driving the agent via `com.privesc.agent.COMMAND`.
