# PE-Reborn Android 17 — row 175: obsolete NXP eSE extensions and JCOP updater

**Date:** 2026-11-07. **Target:** independent AOSP17-based PixelExperience-Reborn for POCO F5 Pro / Redmi K60 (`mondrian`, SM8475). **Scope:** source provenance and non-destructive safety audit. No ROM build, SE APDU execution, firmware/provisioning, hardware access or vendor blob extraction.

## Decision

**Exclude historical `vendor/nxp/secure_element_extns` from the AOSP17 product and manifest**. This repository does **not** provide a modern secure element AIDL HAL, OMAPI service, or a device tree. It exports a historical shared library `ese_client` containing eSE update detection and a JCOP OS downloader. Its purpose was to support the old NXP HAL in row 174; it is not an independently supportable Android17 device feature.

Preserve these **distinct** official AOSP17 sources: `platform/hardware/nxp/secure_element` (vendor SE HAL, AIDL V1), `platform/system/secure_element` (OMAPI service), `platform/hardware/nxp/nfc` (NFC HAL with AIDL V2 option), `platform/packages/modules/Nfc` (NFC Mainline). Never replace them with this archived 14-file vendor library or activate HIDL/JCOP firmware update as a bring-up shortcut.

The verified official AOSP17 Secure Element `android-security-17.0.0_r3` has a **material AIDL channel-index bounds fix** absent from the earlier r1 and the NXP 17.07.00 comparison: see row 174 and the **isolated, nondefault** `aosp17_pe_p2_se_security_candidate.xml`. Preserve this source-level security improvement during any future integration, with a coordinated platform rebase and device tests. **No security patch level or complete November 2026 security compliance is claimed.**

## Pinned sources and ownership

| Git source | Commit | Tree | Meaning |
| --- | --- | --- | --- |
| Historical PE-Reborn `vendor_nxp_secure_element_extns`, `seventeen` | `9794c73f5a5b37116d6a161c4252c82c7ecf0ba0` | `913c5c186f88b43a2db1dd6d9c8b5f02887c50d3` | 2022-01-24. 14 files: `ese_client` HIDL-enabled library, JCOP downloader, update checker, NFC config and CRC32, callbacks. Last commit changes `libnfc-nxp_RF.conf` path; not modern compatibility proof. |
| Historical PE-Reborn `vendor_nxp_secure_element`, `seventeen` | `a171c5ad0105d650d471268733b48d22584cb64a` | `30c1feabe1d5107268ab21494ae4243436e52562` | 2023 P73 eSE HIDL 1.2 service, where `Android.bp` links `ese_client`; old `SpiEseUpdater` and `NxpEseService` can trigger JCOP/Loader Service. |
| Official `platform/hardware/nxp/secure_element`, AOSP17 r1 | `ebc3542b480e505ed67ec52ea0c3135e5902ff5e` | `32593f6a857cc48d52ec6f5c8e7799be2434d6b1` | Primary selected vendor SE HAL source, AIDL V1 `ISecureElement/eSE1`. |
| Official `platform/hardware/nxp/secure_element`, security-r3 | `8aec22fde8121bf3f74006730ce42e9ac0366b62` | `60db7cd2fb71673b3d8468162eaaed6649e3c42c` | **Nondefault** source candidate: 10 changed SE source paths, including AIDL `SecureElement.cpp` and `VirtualISO.cpp` logical-channel bounds checks. |
| NXP `NXPNFCProject/nfcandroid_se_hidlimpl`, `br_ar_17_aosp_mainline` | `582d149bebb97e01ec071bbcfa9a05e356958f50` | `c492237788bf4f0c638d0ae1a352791cdc5eaf1a` | NXP Android17 17.07.00 **read-only vendor comparison**: separate `libese_vendor_extn` implementation, vendor SE AIDL V1, disabled old HIDL/auxiliary update components. |

Sources: https://github.com/PixelExperience-Reborn/vendor_nxp_secure_element_extns/tree/seventeen ; https://github.com/PixelExperience-Reborn/vendor_nxp_secure_element/tree/seventeen ; https://android.googlesource.com/platform/hardware/nxp/secure_element/+/refs/tags/android-17.0.0_r1 ; https://android.googlesource.com/platform/hardware/nxp/secure_element/+/refs/tags/android-security-17.0.0_r3 ; https://github.com/NXPNFCProject/nfcandroid_se_hidlimpl/tree/br_ar_17_aosp_mainline

## Actual old build graph and mutable SE state

1. `Android.bp` builds proprietary `cc_library_shared {name: "ese_client", defaults: ["hidl_defaults"]}`; sources are `utils/phNxpConfig.cc`, `utils/sparse_crc32.cc`, `utils/phNxpLog.cc`, `src/EseUpdateChecker.cc`, `src/JcDnld.cpp`. Dependencies include `libhidlbase`, `libchrome`, `libbase`, `libcutils` etc. There is **no source declaration** of `android.hardware.secure_element.ISecureElement` AIDL or an installable eSE service in this 14-file repo. The 2023 archival SE HAL `Android.bp` includes `ese_client` in shared libraries; the actual installed product and whether this code was invoked are **not proven**.
2. `src/EseUpdateChecker.cc` tests for `/vendor/etc/JcopOs_Update{1,2,3}.apdu` and `/vendor/etc/loaderservice_updater.txt`, reads historical `/data/vendor/nfc/jcop_info.txt` and `/data/vendor/secure_element/jcop_info.txt`, and selects SPI vs NFC/DWP interface using `NXP_ESE_JCOP_DEFAULT_INTERFACE`, `NXP_ESE_LS_DEFAULT_INTERFACE`. Presence/state of such files is **not** a valid OEM authenticity signature or confirmation that the update is safe for mondrian.
3. `src/JcDnld.cpp` implements `JcDnld::doUpdate()` using a worker thread, state-machine transitions, DWP channel `open()`/`transceive()`, JCOP APDU image sequence and persistent update-state files; a `JcopOs_Update*.apdu` chain is **mutating firmware/provisioning territory**. It must not execute in source-audit CI or on a real phone without exact OEM-signed firmware provenance, rollback/provisioning and documented recovery.
4. `utils/phNxpConfig.cc` searches `/odm/etc`, `/vendor/etc`, and optionally `/data/vendor/nfc`, selects `libnfc-nxp.conf`, RF/transit configs and mutable timestamps. The old last commit explicitly updates the RF config path to `/vendor/etc/libnfc-nxp_RF.conf`. These are old configuration conventions, **not** proof that `mondrian` has `/dev/p73`, a PN81x SE or a matching firmware image.
5. In `isOsuRequired(ESE_CLIENT_INTF intf)`, the old code indexes `OSU_STATUS_FILE_PATH_LIST[intf - 1]`. No explicit range check is apparent inside that function. **Record as input-validation review item**, not a claim of reachable memory-corruption or exploitation: callers, enum restrictions, and installed runtime must be traced first. The `JcDnld` downloader also has fixed APDU image paths; no autonomous invocation by a selected Android17 service is claimed.
6. Old config integrity uses CRC32 timestamps, which is **not cryptographic firmware-signature validation**. Do not mistake `sparse_crc32` or file presence for secure boot/OEM image verification.

## Modern AOSP17 and NXP17 architecture is different

- The official SE HAL already has `snxxx/aidl/Android.bp` for `android.hardware.secure_element-service.nxp`, `android.hardware.secure_element-V1-ndk` and an AIDL V1 VINTF fragment `android.hardware.secure_element.ISecureElement/eSE1`. The system OMAPI lives in **`platform/system/secure_element`**, not in the historical `ese_client` module.
- NXP 17.07.00 `libese_vendor_extn/Android.bp` contains **`se_extn_client`, `jcos_client`, `ls_client_snxx_extn`**, each explicitly **`enabled: false`** in the pinned branch. Its independent `libese_vendor_extn/se_update_agent/Android.bp` declares `se_update_agent.nxp` with **`enabled: false`**, and the agent uses `android.se.omapi-V1-ndk` plus the new update script metadata parser.
- **Important nuance**: the modern `snxxx/aidl` SE service includes `:OsuHalCommonFile`, and `snxxx/OsuHal/src/OsuHalExtn.cpp` handles OSU-related APDU modes and reset protection. `enabled: false` for the stand-alone update *agent* does **not** mean an AIDL SE service has no OS-update-related code or that an OEM configuration cannot change runtime. Do not add an extra old helper library or loosen SE/OMAPI policy.
- In the NXP 17.07.00 agent's `.rc`, there is an `on fs` trigger and property-triggered update execution; **do not enable the binary** without a complete update provenance/signature/recovery plan. Disabling the module by default means the source file is not an automatically installed executable: the init text by itself does not prove this service runs on mondrian.
- AOSP17 SE security-r3 hardens `openLogicalChannel` channel index checks for `snxxx/aidl/SecureElement.cpp` and `snxxx/aidl/VirtualISO.cpp`; NXP 17.07.00 vendor snapshot lacks that exact check. A wholesale vendor fork import could regress a reviewed safety fix.

## Completed GitHub source CI — evidence, not hardware validation

[GitHub Actions #42326216221](https://github.com/PixelExperience-Reborn/vendor_nxp_secure_element_extns/actions/runs/42326216221) **SUCCESS**. The actual job logs verified five immutable source **commit/tree** identities: old eSE extns (2022), old SE/P73 HIDL HAL (2023), AOSP17 r1 SE source, official AOSP17 security-r3 SE source, and modern NXP 17.07.00 SE AIDL. The checker proved that the parent old SE HAL links `ese_client`, confirmed the JCOP/DWP downloader source and old APDU/state-file paths, and checked that NXP17's three legacy helper modules, disabled HIDL1.2 service, and stand-alone SE update-agent remain **`enabled: false`**.

It also verified the **exact ten-file official security-r3 source diff**, including the index bounds fix in the two active-style AIDL `openLogicalChannel` implementations. **All 25 AOSP17 staged manifest profiles passed** with independent NFC/SE/OMAPI ownership and the nondefault SE security-r3 candidate unchanged. The whole adversarial manifest test suite passed **44/44**. The output explicitly identifies two **review observations**, not confirmed vulnerabilities: the old `[intf - 1]` path-array access and OSU/reset capabilities within the modern SE implementation.

**Not tested:** Android17 Soong/NDK/OMAPI full build, vendor ABI, SELinux/VINTF assembly, actual eSE/UICC, APDUs or payment, device power/OTA, CTS/VTS, or physical mondrian. `default.xml` and original `seventeen` remain unchanged; no update scripts or firmware have been run.

## Device and platform promotion requirements

1. Verify the real eSE/NFCC/UICC hardware identity, eSE firmware, OEM stock vendor library contract, kernel nodes, VINTF declared instances and SELinux contexts on the user's exact `mondrian` SKU. Do not assert a P73 device or chip solely from archival code. LF52406 LineageOS 24 trees remain at most exceptional **read-only** hardware evidence, never PE-Reborn product basis.
2. Keep the official NXP NFC HAL, official NXP SE HAL and system OMAPI distinct, validate NDK/AIDL versions, Soong modules, runtime Binder service and single matching VINTF instance. No duplicate `ese_client`, HIDL/SE process, arbitrary init trigger or old Java permission framework.
3. No APDU update scripts, JCOP/Loader Service flashing, forced state flags, SE reset, key migration or eSE provisioning without OEM authorization, signature validation, rollback, secure storage and independent recovery instructions. Do **not** put any update files or commands into this audit/CI.
4. Validate CTS/VTS/OMAPI access rules, ARA rules, SE security boundaries, NFC/HCE and recovery/power management after bootable independent PE-Reborn source is built. Test any future security-r3 promotion against this complete SE/OMAPI/NFC device graph; do not claim a current SPL by updating just one repo.
5. Static checked source is not enough to claim functional, payable, CTS-passing, signed or bootable ROM on actual mondrian.

## GitHub implementation

Use isolated `audit/a17-nxp-se-extns-jcop-20261107` with pinned multi-repo source checker and Actions. The manifest work branch `port/a17-aosp17-manifest-20261102` forbids legacy `vendor/nxp/secure_element_extns` checkout/name and owner takeover, keeps `default.xml` source-only safe, checks 25 staged profiles and the isolated SE security-r3 candidate, and updates matrix row 175. Original `seventeen` source remains unchanged.

**Limit:** no full `repo sync`, Soong/NDK build, OTA, device VINTF, firmware operation, hardware tests, VTS/CTS or physical SE validation at this row. A previous row 174 CI has already verified the isolated official SE-r3 `repo manifest` and source-only `repo sync`; this row must not imply repeated hardware tests.
