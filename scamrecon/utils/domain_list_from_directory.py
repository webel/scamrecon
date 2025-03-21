import logging
import os

# Set up logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def extract_domains_from_filenames(directory, output_file="domain_list.txt"):
    """
    Extract domain names from filenames in a directory and write them to a text file.

    Args:
        directory (str): Directory containing files with domain names in filenames
        output_file (str): Path to output text file to create

    Returns:
        int: Number of domains extracted
    """
    # Check if directory exists
    if not os.path.exists(directory):
        logger.error(f"Directory not found: {directory}")
        return 0

    # Get all files in the directory
    files = [
        f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))
    ]

    logger.info(f"Found {len(files)} files in {directory}")

    # Extract domain names from filenames (remove file extension)
    domains = []
    for filename in files:
        # Split the filename by dot and take everything except the last part (file extension)
        parts = filename.split(".")
        if len(parts) > 1:
            # Join all parts except the last one (in case domain itself has dots)
            domain = ".".join(parts[:-1])
            domains.append(domain)

    # Sort domains alphabetically
    domains.sort()

    # Write domains to output file
    with open(output_file, "w") as f:
        for domain in domains:
            f.write(f"{domain}\n")

    logger.info(f"Extracted {len(domains)} domains to {output_file}")
    return len(domains)


# Example usage
if __name__ == "__main__":
    # Change these paths to match your environment
    DEAD_DIR = "screenshots/dead"
    OUTPUT_FILE = "domain_list.txt"

    # Extract domains from filenames
    domain_count = extract_domains_from_filenames(DEAD_DIR, OUTPUT_FILE)
    print(f"Extracted {domain_count} domains to {OUTPUT_FILE}")
