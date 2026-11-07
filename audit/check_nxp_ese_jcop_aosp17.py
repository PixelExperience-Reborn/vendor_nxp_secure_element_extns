#!/usr/bin/env python3
"""PE-Reborn AOSP17 matrix row175: pinned old JCOP updater and modern SE owners.

Source-only, read-only audit. NEVER run APDU/JCOP/Loader Service scripts or
touch /dev/p73, eSE firmware, mobile payment state, vendor partitions or phone.
Inputs: old extns, old SE HAL (row174), official AOSP17 SE, NXP17 SE,
        independent PE-Reborn AOSP17 manifest.
"""
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

LEGACY_SHA = "9794c73f5a5b37116d6a161c4252c82c7ecf0ba0"
LEGACY_TREE = "913c5c186f88b43a2db1dd6d9c8b5f02887c50d3"
OLD_SE_SHA = "a171c5ad0105d650d471268733b48d22584cb64a"
OLD_SE_TREE = "30c1feabe1d5107268ab21494ae4243436e52562"
AOSP_SHA = "ebc3542b480e505ed67ec52ea0c3135e5902ff5e"
AOSP_TREE = "32593f6a857cc48d52ec6f5c8e7799be2434d6b1"
SEC_SHA = "8aec22fde8121bf3f74006730ce42e9ac0366b62"
SEC_TREE = "60db7cd2fb71673b3d8468162eaaed6649e3c42c"
NXP_SHA = "582d149bebb97e01ec071bbcfa9a05e356958f50"
NXP_TREE = "c492237788bf4f0c638d0ae1a352791cdc5eaf1a"
OLD_PATH = "vendor/nxp/secure_element_extns"
OLD_REPO = "vendor_nxp_secure_element_extns"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def git(repo, *args):
    return subprocess.check_output(
        ["git", "-C", str(repo), *args],
        text=True, stderr=subprocess.PIPE).strip()


def pin(repo, ref, sha, tree, label):
    actual = git(repo, "rev-parse", f"{ref}^{{commit}}")
    require(actual == sha, f"{label}: unexpected commit {actual}")
    real_tree = git(repo, "rev-parse", f"{actual}^{{tree}}")
    require(real_tree == tree, f"{label}: unexpected tree {real_tree}")
    return actual


def show(repo, commit, path):
    return git(repo, "show", f"{commit}:{path}")


def paths(repo, commit):
    return git(repo, "ls-tree", "-r", "--name-only", commit).splitlines()


def check_archived_extns(repo):
    sha = pin(repo, "refs/remotes/origin/seventeen",
              LEGACY_SHA, LEGACY_TREE, "2022 archived eSE JCOP extns")
    files = paths(repo, sha)
    require(len(files) == 14, f"legacy eSE extns file inventory {len(files)}")
    bp = show(repo, sha, "Android.bp")
    checker = show(repo, sha, "src/EseUpdateChecker.cc")
    jc = show(repo, sha, "src/JcDnld.cpp")
    hdr = show(repo, sha, "inc/EseUpdateChecker.h")
    config = show(repo, sha, "utils/phNxpConfig.cc")
    crc = show(repo, sha, "utils/sparse_crc32.cc")

    for token in ('name: "ese_client"', 'defaults: ["hidl_defaults"]',
                  'proprietary: true', '"libhidlbase"', '"libchrome"',
                  '"src/EseUpdateChecker.cc"', '"src/JcDnld.cpp"',
                  '"utils/phNxpConfig.cc"', '"utils/sparse_crc32.cc"'):
        require(token in bp, f"old eSE HIDL client build graph changed: {token}")
    require("android.hardware.secure_element-service.nxp" not in bp
            and "android.hardware.secure_element-V1-ndk" not in bp,
            "archival library unexpectedly has new SE AIDL modules")
    for marker in ('"/vendor/etc/JcopOs_Update1.apdu"',
                   '"/vendor/etc/JcopOs_Update2.apdu"',
                   '"/vendor/etc/JcopOs_Update3.apdu"',
                   '"/vendor/etc/loaderservice_updater.txt"',
                   '"/data/vendor/nfc/jcop_info.txt"',
                   '"/data/vendor/secure_element/jcop_info.txt"',
                   "EseUpdateChecker::checkEseUpdateRequired",
                   "EseUpdateChecker::isOsuRequired",
                   "OSU_STATUS_FILE_PATH_LIST[intf - 1]"):
        require(marker in checker, f"archived update detection changed: {marker}")
    for marker in ("JcDnld::doUpdate()", "JcDnld::StartDownload()",
                   "JcDnld::osuUpdateSeqHandler()",
                   "JcDnld::SwitchToJcopOsuState(",
                   '"/vendor/etc/JcopOs_Update1.apdu"',
                   '"/data/vendor/secure_element/jcop_info.txt"'):
        require(marker in jc, f"legacy JCOP downloader changed: {marker}")
    for marker in ('#define JCOP_UPDATE_3STEP_DONE 3',
                   'ESE_INTF_NFC = 1', 'ESE_INTF_SPI = 2'):
        require(marker in hdr, f"old JCOP update interface/state changed: {marker}")
    for marker in ('"/vendor/etc/libnfc-nxp_RF.conf"',
                   '"/data/vendor/nfc/libnfc-nxpConfigState.bin"',
                   '"/data/vendor/nfc/libnfc-nxpTransit.conf"'):
        require(marker in config, f"old NXP NFC config/caching path changed: {marker}")
    require("uint32_t sparse_crc32(" in crc
            and "CRC-32" in crc,
            "old CRC32 non-cryptographic source changed")
    print("PASS: pinned 2022 14-file ese_client is old HIDL/JCOP library, not AIDL")
    print("PASS: fixed JCOP APDU image, LS script and vendor data state paths identified")
    print("PASS: legacy library exposes DWP JCOP update and CRC32 config, not signing")
    print("WARN: isOsuRequired indexes [intf - 1] without visible local range guard")
    print("WARN: a source audit does not establish runtime reachability or exploitability")


def check_parent_se(repo):
    sha = pin(repo, "refs/remotes/origin/seventeen",
              OLD_SE_SHA, OLD_SE_TREE, "old 2023 NXP P73 SE HAL")
    bp = show(repo, sha, "Android.bp")
    service = show(repo, sha, "1.2/NxpEseService.cpp")
    updater = show(repo, sha, "ese-clients/src/SpiEseUpdater.cpp")
    require('"ese_client"' in bp
            and 'name: "android.hardware.secure_element@1.2-service.p73"' in bp,
            "archived parent SE HAL no longer links old ese_client")
    for marker in ("checkIfEseClientUpdateReqd();",
                   "doEseUpdateIfReqd("):
        require(marker in service,
                "archived eSE updater startup call changed: " + marker)
    require("SpiEseUpdater::handleJcopOsDownload(" in updater,
            "archived parent eSE JCOP download chain changed")
    print("PASS: row174 archived HIDL SE service actually links old ese_client")
    print("PASS: 2023 SE HIDL startup contains updater calls; NOT AOSP17 boot evidence")


def modern_se_aidl(repo, ref, label):
    bp = show(repo, ref, "snxxx/aidl/Android.bp")
    vintf = ET.fromstring(
        show(repo, ref, "snxxx/aidl/secure_element-service-nxp.xml"))
    for marker in ('name: "android.hardware.secure_element-service.nxp"',
                   '"android.hardware.secure_element-V1-ndk"',
                   '"vendor.nxp.nxpnfc_aidl-V1-ndk"',
                   '"libbinder_ndk"'):
        require(marker in bp, f"{label}: modern SE HAL module changed {marker}")
    declared = {
        (h.findtext("name"), h.findtext("version"),
         h.findtext("fqname"), h.get("format"))
        for h in vintf.findall("hal")
    }
    require(declared == {
        ("android.hardware.secure_element", "1", "ISecureElement/eSE1", "aidl")
    }, f"{label}: SE HAL AIDL V1 VINTF changed")
    require("ese_client" not in bp,
            f"{label}: old 2022 eSE JCOP helper unexpectedly linked")
    print(f"PASS: {label} official-style SE AIDL V1 eSE1, not old ese_client")


def official_se(repo):
    baseline = pin(repo, "refs/tags/android-17.0.0_r1",
                   AOSP_SHA, AOSP_TREE, "official AOSP17 NXP SE r1")
    security = pin(repo, "refs/tags/android-security-17.0.0_r3",
                   SEC_SHA, SEC_TREE, "official AOSP17 NXP SE security r3")
    modern_se_aidl(repo, baseline, "AOSP17 r1")
    modern_se_aidl(repo, security, "AOSP17 security r3")
    changed = set(git(repo, "diff", "--name-only", baseline, security).splitlines())
    expected = {
        "pn8x/1.0/SecureElement.cpp",
        "pn8x/1.1/SecureElement.cpp",
        "snxxx/1.0/SecureElement.cpp", "snxxx/1.0/VirtualISO.cpp",
        "snxxx/1.1/SecureElement.cpp", "snxxx/1.1/VirtualISO.cpp",
        "snxxx/1.2/SecureElement.cpp", "snxxx/1.2/VirtualISO.cpp",
        "snxxx/aidl/SecureElement.cpp", "snxxx/aidl/VirtualISO.cpp",
    }
    require(changed == expected,
            f"official AOSP17 SE security r3 source delta changed: {changed ^ expected}")
    guard = "rspApdu.p_data[0] < mMaxChannelCount && rspApdu.p_data[0] > 0"
    for path in ("snxxx/aidl/SecureElement.cpp",
                 "snxxx/aidl/VirtualISO.cpp"):
        require(guard not in show(repo, baseline, path)
                and guard in show(repo, security, path),
                f"official SE security channel bound changed: {path}")
    print("PASS: official SE security r3 exact 10-file bounds fix, AIDL/VirtualISO")
    print("DECISION: leave r3 nondefault until coordinated platform/device testing")


def current_nxp_se(repo):
    ref = pin(repo, "refs/remotes/origin/br_ar_17_aosp_mainline",
              NXP_SHA, NXP_TREE, "NXP Android17 17.07.00 SE")
    require("17.07.00" in show(repo, ref, "README.md"),
            "current NXP17 release identity changed")
    modern_se_aidl(repo, ref, "NXP vendor 17.07.00")
    libs = show(repo, ref, "libese_vendor_extn/Android.bp")
    agent = show(repo, ref,
                 "libese_vendor_extn/se_update_agent/Android.bp")
    agent_rc = show(repo, ref,
                    "libese_vendor_extn/se_update_agent/se_update_agent.nxp.rc")
    osu = show(repo, ref, "snxxx/OsuHal/src/OsuHalExtn.cpp")
    old_hidl = show(repo, ref, "snxxx/1.2/Android.bp")
    for name in ('"se_extn_client"', '"jcos_client"',
                 '"ls_client_snxx_extn"'):
        require("name: " + name in libs,
                f"modern NXP17 helper library changed: {name}")
    require(libs.count("enabled: false") == 3,
            "modern NXP17 old eSE/JCOP/LS helpers not all disabled")
    require('name: "se_update_agent.nxp"' in agent
            and "enabled: false" in agent
            and '"android.se.omapi-V1-ndk"' in agent
            and '"android.hardware.secure_element-V1-ndk"' in agent,
            "modern NXP17 isolated SE updater module changed")
    require('name: "android.hardware.secure_element_snxxx@1.2-service"'
            in old_hidl and "enabled: false" in old_hidl,
            "modern NXP17 legacy HIDL SE service not disabled")
    require("on fs" in agent_rc
            and "start se_update_agent" in agent_rc
            and "vendor.se_update_agent.run_execute" in agent_rc,
            "modern NXP17 SE updater init triggers changed")
    require("phNxpEse_doResetProtection(false)" in osu
            and "phNxpEse_resetJcopUpdate()" in osu,
            "modern AIDL SE OSU/reset protection source changed")
    for path in ("snxxx/aidl/SecureElement.cpp",
                 "snxxx/aidl/VirtualISO.cpp"):
        require("rspApdu.p_data[0] < mMaxChannelCount" not in show(repo, ref, path),
                "NXP 17.07.00 now has bounds guard; review conclusions")
    print("PASS: NXP17 three legacy eSE helper modules, old HIDL and updater disabled")
    print("WARN: NXP17 AIDL SE still carries OSU/reset code and updater init triggers")
    print("WARN: vendor 17.07.00 lacks official security-r3 AIDL channel guard")


def manifest(root):
    root = Path(root)
    default = ET.parse(root / "default.xml").getroot()
    require(len(default) == 1 and default[0].tag == "include"
            and default[0].get("name") == "aosp17_pe_p2_kernel_configs.xml",
            "default.xml safe source-only P2 profile changed")
    base = ET.parse(root / "aosp17_pe_bootstrap.xml").getroot()
    owners = {x.get("path"): x.get("name") for x in base.findall("project")}
    for path, owner in (
        ("hardware/nxp/secure_element", "platform/hardware/nxp/secure_element"),
        ("system/secure_element", "platform/system/secure_element"),
        ("hardware/nxp/nfc", "platform/hardware/nxp/nfc"),
        ("packages/modules/Nfc", "platform/packages/modules/Nfc"),
    ):
        require(owners.get(path) == owner,
                "modern source owner changed: " + path)
    require(OLD_PATH not in owners and OLD_REPO not in owners.values(),
            "archived JCOP client is in active base")
    candidate = list(ET.parse(
        root / "aosp17_pe_p2_se_security_candidate.xml").getroot())
    require(len(candidate) == 3
            and candidate[0].tag == "include"
            and candidate[0].get("name") == "aosp17_pe_p2_kernel_configs.xml"
            and candidate[1].get("name") == "platform/hardware/nxp/secure_element"
            and candidate[2].get("name") == "platform/hardware/nxp/secure_element"
            and candidate[2].get("path") == "hardware/nxp/secure_element"
            and candidate[2].get("revision") == SEC_SHA,
            "isolated SE security bounds candidate changed")
    validator = (root / "tools/validate_aosp17_base_profiles.py").read_text()
    tests = (root / "tools/test_aosp17_manifest_entrypoint.py").read_text()
    require(f'if "{OLD_PATH}" in projects:' in validator
            and f'"{OLD_REPO}"' in validator,
            "row175 archive checkout/name deny-list absent")
    for method in (
        "test_old_nxp_jcop_ese_client_cannot_enter_aosp17",
        "test_old_nxp_jcop_client_cannot_replace_official_se_aidl",
        "test_old_nxp_jcop_client_cannot_replace_system_omapi",
    ):
        require(f"def {method}(" in tests,
                f"missing row175 negative regression test: {method}")
    subprocess.run(
        [sys.executable, str(root / "tools/validate_aosp17_base_profiles.py")],
        cwd=root, check=True)
    print("PASS: 25 manifest stages, protected NFC/SE/OMAPI owners and SE-r3 candidate")


def main():
    require(len(sys.argv) == 6,
            "Usage: checker OLD_EXTNS OLD_P73_SE AOSP17_SE NXP17_SE MANIFEST")
    old, parent, official, newer, mf = (
        Path(x).resolve() for x in sys.argv[1:]
    )
    require(all(x.is_dir() for x in (old, parent, official, newer, mf)),
            "one or more verified source checkouts missing")
    check_archived_extns(old)
    check_parent_se(parent)
    official_se(official)
    current_nxp_se(newer)
    manifest(mf)
    print("PASS: row175 old JCOP eSE extns excluded from AOSP17 source graph")
    print("NOT TESTED: Soong/NDK, eSE/APDU, OMAPI VTS/CTS, firmware or mondrian")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, ET.ParseError,
            subprocess.CalledProcessError) as exc:
        print("FAIL:", exc, file=sys.stderr)
        sys.exit(1)
