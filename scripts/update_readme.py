import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def update_readme():
    print("Updating README.md...")
    readme_path = os.path.join(BASE_DIR, "README.md")

    # Header
    content = "Apple CVEs\n\nThis repository contains scripts for monitoring Apple Security Advisories, finding available CVEs and exploits.\n\n## Total CVEs\n\n| Severity | Count |\n| :--- | :--- |\n"

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

    # Order severities
    severities = severity_counts.keys()

    for severity in severities:
        severity_dir = os.path.join(BASE_DIR, severity)
        if not os.path.exists(severity_dir):
            continue

        # Get CVEs in this severity
        cves = sorted([d for d in os.listdir(severity_dir) if d.startswith("CVE-")])

        for cve in cves:
            cve_dir = os.path.join(severity_dir, cve)
            if not os.path.isdir(cve_dir):
                continue

            platforms = sorted(
                [
                    d
                    for d in os.listdir(cve_dir)
                    if os.path.isdir(os.path.join(cve_dir, d))
                ]
            )
            platform_links = []

            for platform in platforms:
                link_path = f"{severity}/{cve}/{platform}/advisory.md"
                # Check directly if file exists just to be safe, though structure implies it
                if os.path.exists(os.path.join(cve_dir, platform, "advisory.md")):
                    platform_links.append(f"[{platform}]({link_path})")

            if platform_links:
                severity_counts[severity] += 1

    for severity in severities:
        content += f"| {severity} | {severity_counts[severity]} |\n"

    with open(readme_path, "w", encoding="utf-8") as f:
        f.write(content)
    print("README.md updated.")


if __name__ == "__main__":
    update_readme()
