#!/usr/bin/env python3
"""
Network Entity Extractor

This script extracts and formats all entities from a network JSON file,
organizing them by type and flagging those with detections. It generates
comprehensive reports to help security analysts and researchers understand
the network structure and identify potentially malicious entities.

The script analyzes IP addresses, domains, files, and their relationships,
providing detailed statistics and connection information.

Usage:
    python extract_entities.py network_104_21_31_200.json output_directory

The script will create separate files for each entity type with detailed information.

Author: Security Analyst
Version: 1.0
Date: March 19, 2025
"""

import csv
import json
import os
import sys
from collections import Counter, defaultdict


def load_network_data(file_path):
    """Load network data from a JSON file."""
    with open(file_path, "r") as file:
        return json.load(file)


def extract_entities(network_data):
    """Extract and categorize entities from network data."""
    entities = {
        "ip_addresses": [],
        "domains": [],
        "files": [],
        "relationships": [],
        "whois": [],
    }

    # Extract entities by type
    for node in network_data["nodes"]:
        node_type = node["type"]

        if node_type == "ip_address":
            entities["ip_addresses"].append(node)
        elif node_type == "domain":
            entities["domains"].append(node)
        elif node_type == "file":
            entities["files"].append(node)
        elif node_type == "relationship":
            entities["relationships"].append(node)
        elif node_type == "whois":
            entities["whois"].append(node)

    return entities


def analyze_connections(network_data, entities):
    """Analyze connections between entities."""
    connections = defaultdict(list)

    # Create a lookup dictionary for quick node access
    node_lookup = {node["entity_id"]: node for node in network_data["nodes"]}

    # Process links
    for link in network_data["links"]:
        source = link["source"]
        target = link["target"]
        connection_type = link["connection_type"]

        # Add connection details
        connections[source].append(
            {
                "target": target,
                "type": connection_type,
                "target_node_type": node_lookup.get(target, {}).get("type", "unknown"),
            }
        )

    return connections


def generate_ip_report(ip_addresses, connections, output_file):
    """Generate a report of IP addresses."""
    with open(output_file, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["IP Address", "Country", "Has Detections", "Connection Count"])

        for ip in ip_addresses:
            entity_id = ip["entity_id"]
            country = ip["entity_attributes"].get("country", "Unknown")
            has_detections = ip["entity_attributes"].get("has_detections", False)
            connection_count = len(connections.get(entity_id, []))

            writer.writerow([entity_id, country, has_detections, connection_count])


def generate_domain_report(domains, connections, output_file):
    """Generate a report of domains."""
    with open(output_file, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Domain", "Has Detections", "Connection Count", "TLD"])

        for domain in domains:
            entity_id = domain["entity_id"]
            has_detections = domain["entity_attributes"].get("has_detections", False)
            connection_count = len(connections.get(entity_id, []))

            # Extract TLD
            domain_parts = entity_id.split(".")
            tld = domain_parts[-1] if len(domain_parts) > 1 else "Unknown"

            writer.writerow([entity_id, has_detections, connection_count, tld])


def generate_file_report(files, connections, output_file):
    """Generate a report of files."""
    with open(output_file, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["File Hash", "Type", "Has Detections", "Connection Count"])

        for file_node in files:
            entity_id = file_node["entity_id"]
            file_type = file_node["entity_attributes"].get("type_tag", "Unknown")
            has_detections = file_node["entity_attributes"].get("has_detections", False)
            connection_count = len(connections.get(entity_id, []))

            writer.writerow([entity_id, file_type, has_detections, connection_count])


def generate_relationship_report(relationships, connections, output_file):
    """Generate a report of relationships."""
    with open(output_file, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Relationship ID", "Relationship Text", "Connection Count"])

        for relationship in relationships:
            entity_id = relationship["entity_id"]
            text = relationship.get("text", "No description")
            connection_count = len(connections.get(entity_id, []))

            writer.writerow([entity_id, text, connection_count])


def generate_connection_report(connections, node_lookup, output_file):
    """Generate a detailed report of connections."""
    with open(output_file, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(
            ["Source", "Source Type", "Target", "Target Type", "Connection Type"]
        )

        for source, targets in connections.items():
            source_node = node_lookup.get(source, {})
            source_type = source_node.get("type", "Unknown")

            for target_info in targets:
                target = target_info["target"]
                target_node = node_lookup.get(target, {})
                target_type = target_node.get("type", "Unknown")
                connection_type = target_info["type"]

                writer.writerow(
                    [source, source_type, target, target_type, connection_type]
                )


def export_entities_to_json(entities, output_dir):
    """Export each entity type to a separate JSON file."""
    os.makedirs(output_dir, exist_ok=True)

    for entity_type, entity_list in entities.items():
        output_file = os.path.join(output_dir, f"{entity_type}.json")
        with open(output_file, "w") as file:
            json.dump(entity_list, file, indent=2)

    print(f"Exported entity data to JSON files in {output_dir}")


def generate_malicious_entities_list(entities, output_file):
    """Generate a list of all malicious entities."""
    with open(output_file, "w") as file:
        file.write("# Malicious Entities List\n\n")

        # Malicious domains
        file.write("## Malicious Domains\n\n")
        for domain in entities["domains"]:
            if domain["entity_attributes"].get("has_detections", False):
                file.write(f"- {domain['entity_id']}\n")

        # Malicious IPs
        file.write("\n## Malicious IP Addresses\n\n")
        for ip in entities["ip_addresses"]:
            if ip["entity_attributes"].get("has_detections", False):
                country = ip["entity_attributes"].get("country", "Unknown")
                file.write(f"- {ip['entity_id']} ({country})\n")

        # Malicious files
        file.write("\n## Malicious Files\n\n")
        for file_node in entities["files"]:
            if file_node["entity_attributes"].get("has_detections", False):
                file_type = file_node["entity_attributes"].get("type_tag", "Unknown")
                file.write(f"- {file_node['entity_id']} ({file_type})\n")


def generate_summary_report(entities, connections, node_lookup, output_file):
    """Generate a summary report of the network analysis.

    Args:
        entities (dict): Dictionary containing lists of entities by type.
        connections (dict): Dictionary of connections between entities.
        node_lookup (dict): Dictionary for quick entity lookup by ID.
        output_file (str): Path to the output file.
    """
    with open(output_file, "w") as file:
        file.write("Network Analysis Summary\n")
        file.write("=======================\n\n")

        # Count entities
        file.write("Entity Counts:\n")
        for entity_type, entity_list in entities.items():
            file.write(f"- {entity_type}: {len(entity_list)}\n")

        # Count malicious entities
        malicious_domains = sum(
            1
            for d in entities["domains"]
            if d["entity_attributes"].get("has_detections", False)
        )
        malicious_ips = sum(
            1
            for ip in entities["ip_addresses"]
            if ip["entity_attributes"].get("has_detections", False)
        )
        malicious_files = sum(
            1
            for f in entities["files"]
            if f["entity_attributes"].get("has_detections", False)
        )

        file.write("\nMalicious Entity Counts:\n")
        if entities["domains"]:
            file.write(
                f"- Malicious domains: {malicious_domains}/{len(entities['domains'])} ({malicious_domains/len(entities['domains'])*100:.1f}%)\n"
            )
        if entities["ip_addresses"]:
            file.write(
                f"- Malicious IPs: {malicious_ips}/{len(entities['ip_addresses'])} ({malicious_ips/len(entities['ip_addresses'])*100:.1f}%)\n"
            )
        if entities["files"]:
            file.write(
                f"- Malicious files: {malicious_files}/{len(entities['files'])} ({malicious_files/len(entities['files'])*100:.1f}%)\n"
            )

        # Connection summary
        file.write("\nConnection Summary:\n")
        file.write(
            f"- Total connections: {sum(len(targets) for targets in connections.values())}\n"
        )

        # Most connected entities
        top_connected = sorted(
            [(source, len(targets)) for source, targets in connections.items()],
            key=lambda x: x[1],
            reverse=True,
        )[:10]

        file.write("\nTop 10 Most Connected Entities:\n")
        for entity_id, connection_count in top_connected:
            entity_node = node_lookup.get(entity_id, {})
            entity_type = entity_node.get("type", "Unknown")
            file.write(
                f"- {entity_id} ({entity_type}): {connection_count} connections\n"
            )

        # File type distribution
        if entities["files"]:
            from collections import Counter

            file_types = Counter(
                [
                    f["entity_attributes"].get("type_tag", "Unknown")
                    for f in entities["files"]
                ]
            )

            file.write("\nFile Type Distribution:\n")
            for file_type, count in file_types.items():
                file.write(f"- {file_type}: {count}\n")

        # Domain TLD distribution
        if entities["domains"]:
            tlds = []
            for domain in entities["domains"]:
                domain_parts = domain["entity_id"].split(".")
                if len(domain_parts) > 1:
                    tlds.append(domain_parts[-1])

            if tlds:
                from collections import Counter

                tld_counts = Counter(tlds)

                file.write("\nTop Level Domain Distribution:\n")
                for tld, count in tld_counts.most_common(10):
                    file.write(f"- .{tld}: {count}\n")

        # Country distribution for IPs
        if entities["ip_addresses"]:
            from collections import Counter

            countries = Counter(
                [
                    ip["entity_attributes"].get("country", "Unknown")
                    for ip in entities["ip_addresses"]
                ]
            )

            file.write("\nIP Address Country Distribution:\n")
            for country, count in countries.most_common():
                file.write(f"- {country}: {count}\n")


def main():
    """Main function to run the script."""
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <network_json_file> <output_directory>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_dir = sys.argv[2]

    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    # Load network data
    print(f"Loading network data from {input_file}...")
    network_data = load_network_data(input_file)

    # Extract entities
    print("Extracting entities...")
    entities = extract_entities(network_data)

    # Create a lookup dictionary for quick node access
    node_lookup = {node["entity_id"]: node for node in network_data["nodes"]}

    # Analyze connections
    print("Analyzing connections...")
    connections = analyze_connections(network_data, entities)

    # Create a lookup dictionary for quick node access
    node_lookup = {node["entity_id"]: node for node in network_data["nodes"]}

    # Generate reports
    print("Generating reports...")

    # Generate entity reports
    generate_ip_report(
        entities["ip_addresses"],
        connections,
        os.path.join(output_dir, "ip_addresses.csv"),
    )
    generate_domain_report(
        entities["domains"], connections, os.path.join(output_dir, "domains.csv")
    )
    generate_file_report(
        entities["files"], connections, os.path.join(output_dir, "files.csv")
    )
    generate_relationship_report(
        entities["relationships"],
        connections,
        os.path.join(output_dir, "relationships.csv"),
    )

    # Generate connection report
    generate_connection_report(
        connections, node_lookup, os.path.join(output_dir, "connections.csv")
    )

    # Generate summary report
    generate_summary_report(
        entities, connections, node_lookup, os.path.join(output_dir, "summary.txt")
    )

    # Generate malicious entities list
    generate_malicious_entities_list(
        entities, os.path.join(output_dir, "malicious_entities.md")
    )

    # Export entities to JSON
    export_entities_to_json(entities, os.path.join(output_dir, "json"))

    print(f"All reports generated in {output_dir}")


if __name__ == "__main__":
    main()
