import os

import requests
from dotenv import load_dotenv


def get_domains_for_ip(api_key, ip_address):
    """
    Retrieves all domains that resolve to a specific IP address.

    Args:
        api_key (str): Your Reverse IP API key
        ip_address (str): The IP address to look up

    Returns:
        list: List of domains resolving to the IP address
    """
    base_url = "https://reverse-ip.whoisxmlapi.com/api/v1"
    all_domains = []
    from_domain = "1"  # Start with the first page

    while True:
        # Construct the API request URL
        params = {"apiKey": api_key, "ip": ip_address, "from": from_domain}

        # Make the API request
        response = requests.get(base_url, params=params)

        # Check if the request was successful
        if response.status_code != 200:
            print(f"Error: API returned status code {response.status_code}")
            print(response.text)
            break

        # Parse the JSON response
        data = response.json()
        print(data)

        # Check if there are domains in the response
        if "result" not in data or len(data["result"]) == 0:
            break

        # Add the domains to our list
        domains = [domain_info["name"] for domain_info in data["result"]]
        all_domains.extend(domains)

        # Check if we've retrieved all domains
        if "size" in data and len(data["result"]) < int(
            data["size"]
        ):  # If we received fewer results than the page size, we're done
            break

        # Set the from_domain to the last domain in the current response
        from_domain = domains[-1]

        print(f"Retrieved {len(all_domains)} domains so far...")

    return all_domains


if __name__ == "__main__":
    # Replace with your actual API key
    load_dotenv()
    API_KEY = os.getenv("WHOISXML_API_KEY")
    print(API_KEY)

    # The IP address to look up
    ip_to_lookup = input("Enter IP address to look up: ")

    # Get the domains
    domains = get_domains_for_ip(API_KEY, ip_to_lookup)

    # Print the results
    print(f"\nFound {len(domains)} domains pointing to {ip_to_lookup}:")
    for domain in domains:
        print(domain)

    # Optionally save to a file
    save_to_file = input("\nSave results to file? (y/n): ").lower()
    if save_to_file == "y":
        filename = f"domains_for_{ip_to_lookup.replace('.', '_')}.txt"
        with open(filename, "w") as f:
            for domain in domains:
                f.write(domain + "\n")
        print(f"Results saved to {filename}")
