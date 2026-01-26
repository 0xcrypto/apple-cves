
import requests
from bs4 import BeautifulSoup
import os
import re
import time
import nvdlib
from markdownify import markdownify as md

# Constants
APPLE_SECURITY_UPDATES_URL = "https://support.apple.com/en-us/HT201222"
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) # Root of apple-security
SEVERITY_MAPPING = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low"
}
DEFAULT_SEVERITY = "Medium" # Fallback

def get_soup(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        return BeautifulSoup(response.content, 'html.parser')
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return None

def get_nvd_severity(cve_id):
    """
    Fetch severity from NVD API using nvdlib.
    """
    try:
        # Rate limiting is handled by nvdlib automatically or we can add manual sleep
        time.sleep(0.6) # NVD allows 5 requests in a rolling 30 second window without API key (~0.16 req/sec? No, wait. 5 per 30s is very slow. With API is better.)
        # Actually without API key it is slow.
        # Let's try to fetch.
        r = nvdlib.searchCVE(cveId=cve_id)
        if r:
            # Prefer V3.1, then V3.0, then V2
            cve_data = r[0]
            if hasattr(cve_data, 'v31score'):
                return cve_data.v31severity.title()
            elif hasattr(cve_data, 'v30score'):
                return cve_data.v30severity.title()
            elif hasattr(cve_data, 'v2score'):
                 # Map V2 severity
                severity = cve_data.v2severity.upper()
                return severity.title()
    except Exception as e:
        print(f"Failed to fetch NVD data for {cve_id}: {e}")
    
    return None

def scrape_advisory(url, title, date):
    print(f"Scraping advisory: {title} ({url})")
    soup = get_soup(url)
    if not soup:
        return

    # Extract content for markdown
    # Apple advisories usually have a main content div
    # We will try to find the specific content area
    content_div = soup.find('div', {'id': 'sections'})
    if not content_div:
        content_div = soup.find('div', {'class': 'main'})
    
    if content_div:
        content_html = str(content_div)
        markdown_content = md(content_html)
    else:
        markdown_content = md(str(soup))

    # Determine Technology/Platform from title
    # E.g., "About the security content of iOS 17.3" -> iOS
    platform = "Other"
    title_lower = title.lower()
    if "ios" in title_lower:
        platform = "iOS"
    elif "macos" in title_lower or "os x" in title_lower:
        platform = "macOS"
    elif "testwatchos" in title_lower or "watchos" in title_lower:
        platform = "watchOS"
    elif "tvos" in title_lower:
        platform = "tvOS"
    elif "safari" in title_lower:
        platform = "Safari"
    elif "visionos" in title_lower:
        platform = "visionOS"
    
    # Extract CVEs from text
    # Regex to find CVE-YYYY-NNNN
    cve_pattern = r"CVE-\d{4}-\d{4,7}"
    cves = set(re.findall(cve_pattern, markdown_content))
    
    if not cves:
        print(f"No CVEs found in {title}")
        return

    for cve in cves:
        print(f"Processing {cve}...")
        severity = get_nvd_severity(cve)
        
        if not severity:
            severity = DEFAULT_SEVERITY
            print(f"Using default severity {severity} for {cve}")
        else:
            print(f"Found severity {severity} for {cve}")
            
        # Create directories: Severity/CVE/Platform
        # Ensure severity matches our folder naming (Title case)
        if severity.upper() not in SEVERITY_MAPPING:
             # Map unknown severities if possible, else default
             severity = DEFAULT_SEVERITY
        
        dir_path = os.path.join(BASE_DIR, severity, cve, platform)
        os.makedirs(dir_path, exist_ok=True)
        
        file_path = os.path.join(dir_path, "advisory.md")

        if os.path.exists(file_path):
            print(f"Skipping existing advisory at {file_path}")
            continue
        
        # Prepend header to markdown
        final_file_content = f"# {title}\n\n**Date:** {date}\n**Original URL:** {url}\n**Platform:** {platform}\n**CVE:** {cve}\n**Severity:** {severity}\n\n---\n\n{markdown_content}"
        
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(final_file_content)
        print(f"Saved advisory to {file_path}")


def main():
    print("Fetching Apple Security Updates page...")
    soup = get_soup(APPLE_SECURITY_UPDATES_URL)
    if not soup:
        return

    # Find the table of advisories
    # Usually in a table with class "gb-table" or similar, or just the first table
    # Looking for links text like "About the security content of..."
    
    # Limit to top 5 for testing/first run to avoid spamming NVD too hard
    count = 0
    limit = 3 
    
    # Finding links in the table
    # The page structure changes, but finding links containing "About the security content" is a good heuristic
    links = soup.find_all('a', href=True)
    
    for link in links:
        text = link.get_text().strip()
        # Filter for product update links, exclude year summaries and archives
        if "Apple security updates" not in text and "archive" not in text.lower():
            # Check if it looks like a product update (contains version numbers or product names)
            if any(x in text for x in ["iOS", "iPadOS", "macOS", "watchOS", "tvOS", "Safari", "Xcode", "visionOS"]):
                href = link['href']
                if href.startswith('/'):
                    href = "https://support.apple.com" + href
                    
                scrape_advisory(href, text, "Unknown Date")
                
                count += 1
                if count >= limit:
                    break
    
    update_readme()

def update_readme():
    print("Updating README.md...")
    readme_path = os.path.join(BASE_DIR, "README.md")
    
    # Header
    content = "# Apple CVEs\n\nThis repository contains scripts for monitoring Apple Security Advisories, finding available CVEs and exploits.\n\n## Scraped CVEs\n\n| Severity | CVE | Platforms |\n| :--- | :--- | :--- |\n"
    
    # Order severities
    severities = ["Critical", "High", "Medium", "Low"]
    
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
                
            platforms = sorted([d for d in os.listdir(cve_dir) if os.path.isdir(os.path.join(cve_dir, d))])
            platform_links = []
            
            for platform in platforms:
                link_path = f"{severity}/{cve}/{platform}/advisory.md"
                # Check directly if file exists just to be safe, though structure implies it
                if os.path.exists(os.path.join(cve_dir, platform, "advisory.md")):
                   platform_links.append(f"[{platform}]({link_path})")
            
            if platform_links:
                content += f"| {severity} | {cve} | {', '.join(platform_links)} |\n"

    with open(readme_path, "w", encoding="utf-8") as f:
        f.write(content)
    print("README.md updated.")

if __name__ == "__main__":
    main()
