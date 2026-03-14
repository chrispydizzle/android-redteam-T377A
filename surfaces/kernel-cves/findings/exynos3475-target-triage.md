# Exynos3475 Target Triage

Date: 2026-03-07

## Conclusion

For the Samsung SM-T377A target, the best surviving kernel-side board match in `exynos_src` is:

- `arch/arm/boot/dts/exynos3475-gteslte_usa_open_00.dts`

Use it together with:

- `arch/arm/boot/dts/exynos3475-gtes_common.dtsi`
- `android_device_samsung_exynos3475-common`

The exact `android_device_samsung_gtesltetmo` device tree referenced by the local manifest is not present locally and was not found publicly during this review.

## Why Revision 00

Captured device properties identify the tablet as:

- model: `SAMSUNG-SM-T377A`
- product: `gteslteuc`
- device: `gteslteatt`
- hardware: `universal3475`
- revision: `0`
- bootloader/baseband: `T377AUCU2AQGF`

Relevant local evidence:

- `work/recon/all_props.txt` contains `ro.product.model = SAMSUNG-SM-T377A`, `ro.product.name = gteslteuc`, and `ro.revision = 0`.
- `work/sysdump_pull/dumpState_T377AUCU2AQGF_202603061424.log` contains `connie=SM-T377A_ATT_USA...`, `androidboot.hardware=universal3475`, and bootloader `T377AUCU2AQGF`.

The `gteslte_usa_open_*` DTS files split by hardware revision as follows:

- `00`: `model_info-hw_rev = <0>` to `<0>`
- `01`: `model_info-hw_rev = <1>` to `<1>`
- `02`: `model_info-hw_rev = <2>` to `<4>`
- `05`: `model_info-hw_rev = <5>` to `<6>`
- `07`: `model_info-hw_rev = <7>` to `<7>`
- `08`: `model_info-hw_rev = <8>` to `<255>`

Since the target device reports `ro.revision = 0`, revision `00` is the strongest board-specific fit.

## Tree Classification

### Keep

- `exynos_src/local_manifest/gtesltetmo.xml`
- `exynos_src/android_device_samsung_exynos3475-common`
- `exynos_src/android_kernel_samsung_exynos3475`
- `exynos_src/android_vendor_samsung/universal3475-common`
- kernel DTS paths matching `gteslte_*`, `gteswifi_*`, and `gtes_common*`

### Reference Only

- `exynos_src/android_device_samsung_universal3475-common`

Reason: useful shared Exynos3475 substrate, but its target filter does not include `gtesltetmo`.

### Archive Or Ignore

- `exynos_src/android_device_samsung_j2lte`
- `exynos_src/android_vendor_samsung/j1xlte`
- `exynos_src/android_vendor_samsung/j2lte`
- `exynos_src/android_vendor_samsung/on5ltetmo`
- kernel DTS families for `j1xlte`, `j2lte`, `j3xlte`, `on5lte`, `o5lte`, `gpvelte`, `novel`, `xcover3ve`

These are mostly phone-family paths and not the right board family for SM-T377A.

## Practical Guidance

- If pruning the repo, keep the tablet-family trees and archive the phone-family trees instead of deleting them outright.
- If reconstructing a missing device tree, start from `android_device_samsung_exynos3475-common` plus the kernel board `gteslte_usa_open_00`.
- If a second-best fallback is needed, use `gteslte_usa_open_01` before any later revision families.