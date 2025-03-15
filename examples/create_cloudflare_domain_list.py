"""
Assisting script to generate an abuse report for Cloudflare
"""

import glob
import json
import os


# Extracts the domain if it is Cloudflare-protected
def check_cloudflare_protected(investigation_file):
    try:
        with open(investigation_file, "r", encoding="utf-8") as f:
            investigation = json.load(f)
            if investigation.get("is_cloudflare_protected") is True:
                return investigation.get("domain")
    except (json.JSONDecodeError, FileNotFoundError, KeyError) as e:
        print(f"Error reading {investigation_file}: {e}")
    return None


def generate_cloudflare_urls():
    output_file = "cloudflare_urls.txt"
    results_dir = os.path.join(os.getcwd(), "results")

    with open(output_file, "w", encoding="utf-8") as f:
        for investigation_file in glob.glob(f"{results_dir}/*_investigation.json"):
            print(f"Checking {investigation_file}")
            cloudflare_protected_url = check_cloudflare_protected(investigation_file)
            if cloudflare_protected_url:
                f.write(cloudflare_protected_url + "\n")

    print(f"Cloudflare-protected URLs saved to {output_file}")


if __name__ == "__main__":
    generate_cloudflare_urls()
