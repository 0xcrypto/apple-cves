
import asyncio
import aiohttp
from bs4 import BeautifulSoup
import os
import re
import time
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
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Rate Limiting Semaphores
# Apple: Can handle moderate concurrency
APPLE_CONCURRENCY = 10
# NVD: Strict limits. 5 requests / 30 seconds without API key.
# We will be very conservative. 1 request every 6.5 seconds to be safe.
NVD_DELAY = 6.5 

async def get_soup(session, url):
    try:
        async with session.get(url) as response:
            response.raise_for_status()
            content = await response.text()
            return BeautifulSoup(content, 'html.parser')
    except Exception as e:
        print(f"Error fetching {url}: {e}")
        return None

async def get_nvd_severity(session, cve_id):
    """
    Fetch severity from NVD API.
    """
    params = {'cveId': cve_id}
    try:
        # Respect rate limit globally? 
        # For simplicity in this script, we sleep *before* requesting if we are processing many.
        # But since we are async, multiple workers might hit this.
        # We need a centralized locker or just a simple delay here might not be enough if parallel.
        # Implemented via a queue in main, but individual call helper:
        
        async with session.get(NVD_API_URL, params=params) as response:
            if response.status == 403 or response.status == 429:
                print(f"Rate limited by NVD for {cve_id} (Status {response.status}). Waiting longer...")
                await asyncio.sleep(30) # Wait out the window
                return await get_nvd_severity(session, cve_id) # Retry
            
            if response.status != 200:
                print(f"NVD API Error {response.status} for {cve_id}")
                return None
                
            data = await response.json()
            if not data.get('vulnerabilities'):
                return None
            
            vuln = data['vulnerabilities'][0]['cve']
            metrics = vuln.get('metrics', {})
            
            # CVSS V3.1
            if 'cvssMetricV31' in metrics:
                 return metrics['cvssMetricV31'][0]['cvssData']['baseSeverity'].title()
            # CVSS V3.0
            elif 'cvssMetricV30' in metrics:
                 return metrics['cvssMetricV30'][0]['cvssData']['baseSeverity'].title()
            # CVSS V2
            elif 'cvssMetricV2' in metrics:
                 return metrics['cvssMetricV2'][0]['baseMetricV2']['severity'].title()
                 
    except Exception as e:
        print(f"Failed to fetch NVD data for {cve_id}: {e}")
    
    return None

async def process_advisory(session, url, title, nvd_queue):
    print(f"Scraping advisory: {title}")
    soup = await get_soup(session, url)
    if not soup:
        return

    content_div = soup.find('div', {'id': 'sections'})
    if not content_div:
        content_div = soup.find('div', {'class': 'main'})
    
    if content_div:
        content_html = str(content_div)
        markdown_content = md(content_html)
    else:
        markdown_content = md(str(soup))

    platforms = []
    title_lower = title.lower()
    if "ios" in title_lower:
        platforms.append("iOS")
    if "ipados" in title_lower:
        platforms.append("iPadOS")
    if "macos" in title_lower or "os x" in title_lower:
        platforms.append("macOS")
    if "watchos" in title_lower:
        platforms.append("watchOS")
    if "tvos" in title_lower:
        platforms.append("tvOS")
    if "visionos" in title_lower:
        platforms.append("visionOS")
    if "safari" in title_lower:
        platforms.append("Safari")
    if "xcode" in title_lower:
        platforms.append("Xcode")
    
    if not platforms:
        platforms.append("Other")
    
    cve_pattern = r"CVE-\d{4}-\d{4,7}"
    cves = set(re.findall(cve_pattern, markdown_content))
    
    if not cves:
        return

    for cve in cves:
        for platform in platforms:
            # Enqueue for NVD processing
            await nvd_queue.put({
                'cve': cve,
                'platform': platform,
                'title': title,
                'url': url,
                'markdown': markdown_content,
                'date': "Unknown Date" 
            })

async def nvd_worker(session, queue):
    """
    Worker to process NVD lookups sequentially to respect rate limits.
    """
    while True:
        item = await queue.get()
        cve = item['cve']
        
        # Optimization: Check if we already know the severity for this CVE
        # by looking for existing directories: BASE_DIR/Severity/CVE-XXXX-XXXX
        known_severity = None
        for s in SEVERITY_MAPPING.values():
            cve_dir = os.path.join(BASE_DIR, s, cve)
            if os.path.isdir(cve_dir):
                known_severity = s
                break
        
        # If we found the CVE folder, we know the severity.
        if known_severity:
            # Check if we already have the advisory for this platform
            file_path = os.path.join(BASE_DIR, known_severity, cve, item['platform'], "advisory.md")
            if os.path.exists(file_path):
                print(f"Skipping {cve} ({item['platform']}) - already exists in {known_severity}")
                queue.task_done()
                continue
            
            # File doesn't exist, but we know severity. Write it immediately.
            # No NVD delay needed!
            severity = known_severity
            print(f"Severity cached for {cve}: {severity}")
            
        else:
            # We don't know severity. Must query NVD.
            print(f"Checking NVD for {cve}...")
            severity = await get_nvd_severity(session, cve)
            
            if not severity:
                severity = DEFAULT_SEVERITY
                print(f"Defaulting {cve} to {severity}")
            else:
                print(f"Resolved {cve} as {severity}")

            if severity.upper() not in SEVERITY_MAPPING:
                 severity = DEFAULT_SEVERITY
            
            # Apply rate limit only if we actually hit the API
            await asyncio.sleep(NVD_DELAY)

        # Create File
        dir_path = os.path.join(BASE_DIR, severity, cve, item['platform'])
        os.makedirs(dir_path, exist_ok=True)
        file_path = os.path.join(dir_path, "advisory.md")
        
        if not os.path.exists(file_path):
            final_file_content = f"# {item['title']}\n\n**Date:** {item['date']}\n**Original URL:** {item['url']}\n**Platform:** {item['platform']}\n**CVE:** {cve}\n**Severity:** {severity}\n\n---\n\n{item['markdown']}"
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(final_file_content)
            print(f"Saved {file_path}")
        else:
            print(f"Skipping write {file_path}")
        
        queue.task_done()

def update_readme():
    print("Updating README.md...")
    readme_path = os.path.join(BASE_DIR, "README.md")
    
    content = "# Apple CVEs\n\nThis repository contains scripts for monitoring Apple Security Advisories, finding available CVEs and exploits.\n\n## Scraped CVEs\n\n"
    
    # Collect all data first
    # Map: CVE -> {severity: S, platforms: {p1: link1, p2: link2}}
    cve_data = {}
    
    all_technologies = ["iOS", "iPadOS", "macOS", "tvOS", "watchOS", "visionOS", "Safari", "Xcode"]
    tech_columns = ["iOS", "iPadOS", "macOS", "tvOS", "watchOS", "visionOS", "Safari", "Xcode"]

    for severity in SEVERITY_MAPPING.values():
        severity_dir = os.path.join(BASE_DIR, severity)
        if not os.path.exists(severity_dir): continue
        
        cves = sorted([d for d in os.listdir(severity_dir) if d.startswith("CVE-")])
        for cve in cves:
            if cve not in cve_data:
                cve_data[cve] = {"severity": severity, "platforms": {}}
            
            # If same CVE in multiple severity folders (shouldn't happen with our logic but finding standard), logic prioritizes last found or consistent.
            # Our scraper ensures 1 severity per CVE usually.
            
            cve_dir = os.path.join(severity_dir, cve)
            if not os.path.isdir(cve_dir): continue
            
            found_platforms = [d for d in os.listdir(cve_dir) if os.path.isdir(os.path.join(cve_dir, d))]
            for p in found_platforms:
                link = f"{severity}/{cve}/{p}/advisory.md"
                cve_data[cve]["platforms"][p] = link

    # Build Table
    # Header
    header = "| CVE | Severity | " + " | ".join(tech_columns) + " | Other |\n"
    separator = "| :--- | :--- | " + " | ".join([":---:"] * len(tech_columns)) + " | :---: |\n"
    content += header + separator
    
    # Sort CVEs reverse chronologically (approx by ID)
    sorted_cves = sorted(cve_data.keys(), reverse=True)
    
    for cve in sorted_cves:
        data = cve_data[cve]
        row = f"| {cve} | {data['severity']} |"
        
        # Tech columns
        for tech in tech_columns:
            if tech in data["platforms"]:
                row += f" [✅]({data['platforms'][tech]}) |"
            else:
                row += " |"
        
        # Other column
        others = []
        for p, link in data["platforms"].items():
            if p not in tech_columns:
                others.append(f"[{p}]({link})")
        
        row += f" {', '.join(others)} |\n"
        content += row

    with open(readme_path, "w", encoding="utf-8") as f:
        f.write(content)
    print("README.md updated.")

async def extract_links_from_soup(soup, session, nvd_queue, tasks, processed_urls):
    links = soup.find_all('a', href=True)
    archive_tasks = []
    for link in links:
        text = link.get_text().strip()
        href = link['href']
        if href.startswith('/'): href = "https://support.apple.com" + href
        
        # Handle Archives
        if "Apple security updates" in text:
            # Check years. We want 2020+.
            # Format: "Apple security updates (2022 to 2023)"
            years = re.findall(r'\d{4}', text)
            if years:
                # If any year in the range is >= 2020
                if any(int(y) >= 2020 for y in years):
                    if href not in processed_urls:
                        print(f"Found archive: {text} - {href}")
                        processed_urls.add(href)
                        # Fetch archive page and extract links recursively (depth 1)
                        # We just spawn a task to fetch archive and process its links
                        tasks.append(process_archive(session, href, nvd_queue, processed_urls))
            continue

        if "archive" in text.lower():
            continue

        if any(x in text for x in ["iOS", "iPadOS", "macOS", "watchOS", "tvOS", "Safari", "Xcode", "visionOS"]):
            if href not in processed_urls:
                processed_urls.add(href)
                archive_tasks.append(process_advisory(session, href, text, nvd_queue))
    
    if archive_tasks:
        print(f"Main Page: Processing {len(archive_tasks)} advisories concurrently...")
        await asyncio.gather(*archive_tasks)
    
    return len(archive_tasks)

async def process_archive(session, url, nvd_queue, processed_urls):
    print(f"Processing archive page: {url}")
    soup = await get_soup(session, url)
    if not soup: return
    
    links = soup.find_all('a', href=True)
    archive_tasks = []
    for link in links:
        text = link.get_text().strip()
        href = link['href']
        if href.startswith('/'): href = "https://support.apple.com" + href

        if any(x in text for x in ["iOS", "iPadOS", "macOS", "watchOS", "tvOS", "Safari", "Xcode", "visionOS"]):
             if "Apple security updates" not in text and "archive" not in text.lower():
                 if href not in processed_urls:
                     processed_urls.add(href)
                     archive_tasks.append(process_advisory(session, href, text, nvd_queue))
    
    if archive_tasks:
        print(f"Archive {url}: Processing {len(archive_tasks)} advisories concurrently...")
        await asyncio.gather(*archive_tasks)

async def main():
    print("Starting async scraper...")
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15"
    }
    async with aiohttp.ClientSession(headers=headers) as session:
        soup = await get_soup(session, APPLE_SECURITY_UPDATES_URL)
        if not soup: return

        nvd_queue = asyncio.Queue()
        # Spawn 3 workers to try and speed up processing
        workers = [asyncio.create_task(nvd_worker(session, nvd_queue)) for _ in range(3)]

        tasks = []
        processed_urls = set()
        
        # Initial extraction from main page (includes discovering archives)
        await extract_links_from_soup(soup, session, nvd_queue, tasks, processed_urls)
        
        # Run gathered tasks (advisories + archives)
        await asyncio.gather(*tasks)
        
        # Wait for queue
        await nvd_queue.join()
        for w in workers:
            w.cancel()
        
    update_readme()

if __name__ == "__main__":
    asyncio.run(main())
