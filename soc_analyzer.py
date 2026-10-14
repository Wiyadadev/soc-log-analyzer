import subprocess
import re
import csv
from pathlib import Path

EVENT_IDS = [1, 3, 11, 22]
REPORT_FILE = Path("soc_report.csv")


def get_events(event_id, max_events=50):
    cmd = [
        "powershell",
        "-Command",
        (
            f"Get-WinEvent -FilterHashtable "
            f"@{{LogName='Microsoft-Windows-Sysmon/Operational';Id={event_id}}} "
            f"-MaxEvents {max_events} | Format-List TimeCreated,Message"
        )
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore"
    )

    return result.stdout


def extract_value(text, key):
    match = re.search(rf"{re.escape(key)}:\s*(.+)", text)
    return match.group(1).strip() if match else "-"


def analyze_event(event_id, block):
    time_created = extract_value(block, "TimeCreated")
    image = extract_value(block, "Image")
    image_lower = image.lower()

    risk = "LOW"
    reasons = []

    risky_paths = [
        "\\temp\\",
        "\\downloads\\",
        "\\appdata\\local\\temp\\"
    ]

    review_processes = [
        "powershell.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe"
    ]

    path_risk = any(path in image_lower for path in risky_paths)
    process_risk = any(proc in image_lower for proc in review_processes)

    if path_risk:
        risk = "REVIEW"
        reasons.append("risky path")

    if process_risk:
        risk = "REVIEW"
        reasons.append("script/command process")

    if image == "<unknown process>":
        risk = "REVIEW"
        reasons.append("unknown process")


    # EVENT ID 1 - Process Create
    if event_id == 1:
        parent = extract_value(block, "ParentImage")
        command = extract_value(block, "CommandLine")

        if path_risk and process_risk:
            risk = "SUSPICIOUS"
            reasons.append("command process from risky path")

        return {
            "time": time_created,
            "event_id": event_id,
            "type": "PROCESS",
            "risk": risk,
            "image": image,
            "detail": f"Parent={parent} | Command={command}",
            "reason": ", ".join(reasons) if reasons else "expected behavior"
        }


    # EVENT ID 3 - Network Connection
    if event_id == 3:
        ip = extract_value(block, "DestinationIp")
        port = extract_value(block, "DestinationPort")
        protocol = extract_value(block, "Protocol")
        initiated = extract_value(block, "Initiated")

        common_ports = ["80", "443", "53", "5353", "-"]

        if port not in common_ports:
            risk = "REVIEW"
            reasons.append("uncommon destination port")

        if path_risk and port not in common_ports:
            risk = "SUSPICIOUS"
            reasons.append("risky path + uncommon port")

        if image == "<unknown process>" and port not in common_ports:
            risk = "SUSPICIOUS"
            reasons.append("unknown process + uncommon port")

        return {
            "time": time_created,
            "event_id": event_id,
            "type": "NETWORK",
            "risk": risk,
            "image": image,
            "detail": (
                f"{ip}:{port} | "
                f"Protocol={protocol} | "
                f"Initiated={initiated}"
            ),
            "reason": ", ".join(reasons) if reasons else "expected network behavior"
        }


    # EVENT ID 11 - File Create
    if event_id == 11:
        filename = extract_value(block, "TargetFilename")
        filename_lower = filename.lower()

        executable_extensions = (
            ".exe",
            ".dll",
            ".ps1",
            ".bat",
            ".cmd",
            ".vbs",
            ".js"
        )

        dangerous_file = filename_lower.endswith(executable_extensions)

        if dangerous_file:
            risk = "REVIEW"
            reasons.append("executable/script created")

        if dangerous_file and (
            "\\temp\\" in filename_lower
            or "\\downloads\\" in filename_lower
        ):
            risk = "SUSPICIOUS"
            reasons.append("executable/script created in risky directory")

        return {
            "time": time_created,
            "event_id": event_id,
            "type": "FILE",
            "risk": risk,
            "image": image,
            "detail": filename,
            "reason": ", ".join(reasons) if reasons else "normal file creation"
        }


    # EVENT ID 22 - DNS Query
    if event_id == 22:
        domain = extract_value(block, "QueryName")
        status = extract_value(block, "QueryStatus")

        return {
            "time": time_created,
            "event_id": event_id,
            "type": "DNS",
            "risk": risk,
            "image": image,
            "detail": f"{domain} | Status={status}",
            "reason": ", ".join(reasons) if reasons else "normal DNS query"
        }

    return None


def save_csv(results):
    with REPORT_FILE.open(
        "w",
        newline="",
        encoding="utf-8-sig"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=[
                "time",
                "event_id",
                "type",
                "risk",
                "image",
                "detail",
                "reason"
            ]
        )

        writer.writeheader()
        writer.writerows(results)


def main():
    print("\n=== SOC LOG ANALYZER v2 ===\n")

    results = []

    counts = {
        "LOW": 0,
        "REVIEW": 0,
        "SUSPICIOUS": 0
    }

    for event_id in EVENT_IDS:
        data = get_events(event_id)

        if not data.strip():
            continue

        blocks = re.split(r"\r?\n\r?\n", data)

        for block in blocks:
            if "Message" not in block:
                continue

            result = analyze_event(event_id, block)

            if not result:
                continue

            results.append(result)
            counts[result["risk"]] += 1

            print(
                f"[{result['risk']}] "
                f"[{result['type']}] "
                f"{result['image']} -> "
                f"{result['detail']}"
            )

    save_csv(results)

    print("\n=== SUMMARY ===")
    print(f"LOW        : {counts['LOW']}")
    print(f"REVIEW     : {counts['REVIEW']}")
    print(f"SUSPICIOUS : {counts['SUSPICIOUS']}")
    print(f"TOTAL      : {len(results)}")

    print(f"\nReport saved: {REPORT_FILE.resolve()}")


if __name__ == "__main__":
    main()