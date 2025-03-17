"""
Screenshot Similarity Analyzer

This script analyzes screenshot images for visual similarity,
groups them based on their similarity, and integrates with the abuse report generator.

Dependencies:
- Python 3.8+
- OpenCV (cv2)
- NumPy
- PIL (Pillow)
- scikit-image
"""

import json
import os
import re
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

import cv2
import numpy as np
from PIL import Image
from skimage.metrics import structural_similarity as ssim

# Configuration for the similarity analysis
CONFIG = {
    # Image dimensions to resize all screenshots to for comparison
    "target_width": 800,
    "target_height": 600,
    # Similarity thresholds
    "orb_match_threshold": 0.35,  # Lower value = more strict matching (0.0 to 1.0)
    "ssim_threshold": 0.70,  # Higher value = more strict matching (0.0 to 1.0)
    # Grouping thresholds
    "min_similarity_for_group": 0.70,  # Minimum similarity to consider screenshots part of the same group
    # Analysis methods
    "use_feature_matching": True,  # Use OpenCV feature matching (more accurate but slower)
    "use_ssim": True,  # Use structural similarity index (good balance)
    # Parallelization
    "max_workers": 8,  # Number of parallel workers for image processing
    # Output options
    "generate_grouped_images": True,  # Create composite images for each group
    "generate_report": True,  # Generate a JSON report of groups
}


class ScreenshotAnalyzer:
    """Class for managing and analyzing screenshot images."""

    def __init__(self, options=None):
        """
        Initialize the ScreenshotAnalyzer.

        Args:
            options: Optional dict to override default configuration
        """
        self.config = {**CONFIG, **(options or {})}
        self.screenshots = []
        self.similarity_matrix = []
        self.groups = []

    def load_screenshots(self, directory_path: str) -> None:
        """
        Load all screenshots from a directory.

        Args:
            directory_path: Path to directory containing screenshots
        """
        print(f"Loading screenshots from {directory_path}...")

        files = [
            f
            for f in os.listdir(directory_path)
            if os.path.isfile(os.path.join(directory_path, f))
        ]
        image_files = [
            f for f in files if f.lower().endswith((".png", ".jpg", ".jpeg", ".webp"))
        ]

        print(f"Found {len(image_files)} image files.")
        
        # Group images by file size first to help identify duplicates
        size_to_files = {}
        for file in image_files:
            file_path = os.path.join(directory_path, file)
            file_size = os.path.getsize(file_path)
            if file_size not in size_to_files:
                size_to_files[file_size] = []
            size_to_files[file_size].append(file)
        
        # Print duplicates based on file size
        duplicate_sizes = {size: files for size, files in size_to_files.items() if len(files) > 1}
        if duplicate_sizes:
            print("\nFound potential duplicate screenshots (identical file sizes):")
            for size, files in duplicate_sizes.items():
                print(f"  Size {size} bytes: {len(files)} files")
                if len(files) <= 10:
                    print(f"    {', '.join(files)}")
                else:
                    print(f"    {', '.join(files[:5])}... and {len(files) - 5} more")
            print("")

        # Load each image and prepare it for analysis
        for i, file in enumerate(image_files):
            file_path = os.path.join(directory_path, file)
            domain = self.extract_domain_from_filename(file)
            file_size = os.path.getsize(file_path)

            try:
                # Load and resize the image for consistent comparison
                img = cv2.imread(file_path)
                if img is None:
                    print(f"Warning: Could not read image {file_path}")
                    continue

                resized_img = cv2.resize(
                    img,
                    (self.config["target_width"], self.config["target_height"]),
                    interpolation=cv2.INTER_AREA,
                )

                self.screenshots.append(
                    {
                        "path": file_path,
                        "filename": file,
                        "domain": domain,
                        "image": resized_img,
                        "width": self.config["target_width"],
                        "height": self.config["target_height"],
                        "file_size": file_size,  # Store file size to help identify duplicates
                        "features": None,  # Will be populated during feature extraction
                    }
                )

                if (i + 1) % 10 == 0:
                    print(f"Loaded {i + 1} screenshots...")
            except Exception as e:
                print(f"Error loading image {file}: {str(e)}")

        print(f"Successfully loaded {len(self.screenshots)} screenshots.")

    def extract_domain_from_filename(self, filename: str) -> str:
        """
        Extract domain name from screenshot filename.

        Args:
            filename: Filename of the screenshot

        Returns:
            Domain name or original filename if pattern not found
        """
        # Try to extract domain from filename patterns like "screenshot_example.com.png"
        patterns = [
            r"screenshot[_-]([^_\-.]+\.[^_\-.]+)\.",
            r"([^_\-.]+\.[^_\-.]+)[_-]screenshot\.",
            r"([^_\-.]+\.[^_\-.]+)\.",
        ]

        for pattern in patterns:
            match = re.search(pattern, filename, re.IGNORECASE)
            if match and match.group(1):
                return match.group(1).lower()

        # Return the filename without extension if no pattern matches
        return os.path.splitext(filename)[0]

    def analyze_similarity(self) -> None:
        """Analyze all screenshots for similarity."""
        print("Starting similarity analysis...")

        num_screenshots = len(self.screenshots)

        # Extract features from images if using feature matching
        if self.config["use_feature_matching"]:
            self.extract_features()

        # Initialize similarity matrix
        self.similarity_matrix = np.zeros((num_screenshots, num_screenshots))

        # Compare each screenshot with every other screenshot
        comparisons = []

        for i in range(num_screenshots):
            # A screenshot is always 100% similar to itself
            self.similarity_matrix[i, i] = 1.0

            for j in range(i + 1, num_screenshots):
                comparisons.append((i, j))

        # Process comparisons in parallel
        with ThreadPoolExecutor(max_workers=self.config["max_workers"]) as executor:
            future_to_indices = {
                executor.submit(self.compare_screenshots, i, j): (i, j)
                for i, j in comparisons
            }

            completed = 0
            for future in as_completed(future_to_indices):
                i, j = future_to_indices[future]
                try:
                    similarity = future.result()
                    self.similarity_matrix[i, j] = similarity
                    self.similarity_matrix[j, i] = similarity  # Symmetric matrix

                    completed += 1
                    if completed % 100 == 0:
                        print(
                            f"Processed {completed}/{len(comparisons)} image comparisons..."
                        )
                except Exception as e:
                    print(f"Error comparing screenshots {i} and {j}: {str(e)}")

        print("Similarity analysis complete.")

    def compare_screenshots(self, i: int, j: int) -> float:
        """
        Compare two screenshots and return their similarity score.

        Args:
            i: Index of first screenshot
            j: Index of second screenshot

        Returns:
            Similarity score between 0.0 and 1.0
        """
        # Same screenshot - perfect match
        if i == j:
            return 1.0
            
        # Check file size first - identical sizes are strong indicators of duplicates
        if (hasattr(self.screenshots[i], 'file_size') and 
            hasattr(self.screenshots[j], 'file_size') and
            self.screenshots[i]['file_size'] == self.screenshots[j]['file_size'] and
            self.screenshots[i]['file_size'] > 10000):  # Only consider substantial file sizes (>10KB)
            # File path contains same hostname pattern - very likely same site
            domain_i = self.screenshots[i]['domain']
            domain_j = self.screenshots[j]['domain']
            
            # If both domains share the same base (e.g., evviva, marriot, etc)
            if domain_i and domain_j:
                if (domain_i[:5] == domain_j[:5] and len(domain_i) > 5 and len(domain_j) > 5):
                    return 0.95  # Very high likelihood of being the same site
        
        similarity_scores = []

        # Use structural similarity if enabled
        if self.config["use_ssim"]:
            ssim_score = self.calculate_ssim(self.screenshots[i], self.screenshots[j])
            similarity_scores.append(ssim_score)

        # Use feature matching if enabled
        if self.config["use_feature_matching"]:
            feature_score = self.calculate_feature_similarity(
                self.screenshots[i], self.screenshots[j]
            )
            similarity_scores.append(feature_score)

        # Return average of all used similarity measures
        if similarity_scores:
            similarity = sum(similarity_scores) / len(similarity_scores)
            
            # Debug output for high similarity scores
            if similarity > 0.6:
                print(f"Similarity between {self.screenshots[i]['domain']} and {self.screenshots[j]['domain']}: {similarity:.4f}")
                
            return similarity
        return 0.0

    def extract_features(self) -> None:
        """Extract image features for all screenshots using OpenCV."""
        print("Extracting image features...")

        # Initialize ORB feature detector
        orb = cv2.ORB_create()

        for i, screenshot in enumerate(self.screenshots):
            try:
                # Convert to grayscale for feature detection
                gray = cv2.cvtColor(screenshot["image"], cv2.COLOR_BGR2GRAY)

                # Detect keypoints and compute descriptors
                keypoints, descriptors = orb.detectAndCompute(gray, None)

                # Store features in screenshot object
                self.screenshots[i]["features"] = {
                    "keypoints": keypoints,
                    "descriptors": descriptors,
                }

                if (i + 1) % 10 == 0:
                    print(f"Extracted features from {i + 1} screenshots...")
            except Exception as e:
                print(f"Error extracting features from screenshot {i}: {str(e)}")
                self.screenshots[i]["features"] = {"keypoints": [], "descriptors": None}

        print("Feature extraction complete.")

    def calculate_ssim(self, screenshot1: Dict, screenshot2: Dict) -> float:
        """
        Calculate structural similarity between two screenshots.

        Args:
            screenshot1: First screenshot object
            screenshot2: Second screenshot object

        Returns:
            Similarity score between 0.0 and 1.0
        """
        try:
            # Special case: If we're comparing the same image file, return 1.0
            if screenshot1["path"] == screenshot2["path"]:
                return 1.0
                
            # Check for byte-identical image data - these are definitely identical
            if np.array_equal(screenshot1["image"], screenshot2["image"]):
                return 1.0
                
            # If file sizes are identical (approximated via pixel equality), this is a strong indicator of identical screenshots
            identical_pixels = np.sum(screenshot1["image"] == screenshot2["image"]) / screenshot1["image"].size
            if identical_pixels > 0.99:  # Over 99% identical pixels
                return 1.0
            
            # Convert images to grayscale for SSIM
            gray1 = cv2.cvtColor(screenshot1["image"], cv2.COLOR_BGR2GRAY)
            gray2 = cv2.cvtColor(screenshot2["image"], cv2.COLOR_BGR2GRAY)
            
            # Calculate SSIM
            score, _ = ssim(gray1, gray2, full=True)
            similarity = max(0.0, min(score, 1.0))  # Ensure score is between 0 and 1
            
            # Boost similarity scores that are already high to help with grouping
            if similarity >= 0.9:
                similarity = 1.0
            elif similarity >= 0.85:
                similarity = min(0.95, similarity * 1.05)
                
            return similarity
            
        except Exception as e:
            print(f"Error calculating SSIM: {str(e)}")
            return 0.0

    def calculate_feature_similarity(
        self, screenshot1: Dict, screenshot2: Dict
    ) -> float:
        """
        Calculate feature-based similarity between two screenshots using OpenCV.

        Args:
            screenshot1: First screenshot object
            screenshot2: Second screenshot object

        Returns:
            Similarity score between 0.0 and 1.0
        """
        try:
            features1 = screenshot1["features"]
            features2 = screenshot2["features"]

            # If either image has no features, they're not similar
            if (
                not features1
                or not features2
                or not features1["keypoints"]
                or not features2["keypoints"]
                or features1["descriptors"] is None
                or features2["descriptors"] is None
            ):
                return 0.0
                
            # Special case: If we're comparing the same image file, return 1.0
            if screenshot1["path"] == screenshot2["path"]:
                return 1.0

            # Check for byte-identical image data - these are definitely identical
            if np.array_equal(screenshot1["image"], screenshot2["image"]):
                return 1.0
                
            # If file sizes are identical, this is a strong indicator of identical screenshots
            # (We don't have access to file sizes directly, but we can check identical pixel data)
            identical_pixels = np.sum(screenshot1["image"] == screenshot2["image"]) / screenshot1["image"].size
            if identical_pixels > 0.99:  # Over 99% identical pixels
                return 1.0

            # Match features using Brute Force matcher
            bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=True)
            
            # Handle case where descriptors might be empty but not None
            if len(features1["descriptors"]) == 0 or len(features2["descriptors"]) == 0:
                return 0.0
                
            matches = bf.match(features1["descriptors"], features2["descriptors"])

            # Sort matches by distance (lower is better)
            matches = sorted(matches, key=lambda x: x.distance)

            # Calculate good matches based on threshold
            if not matches:
                return 0.0

            # Adjust the good match threshold to be more permissive - original is too strict
            ratio_threshold = min(0.85, self.config["orb_match_threshold"] * 2.0)
            
            good_matches_count = sum(
                1
                for m in matches
                if m.distance < ratio_threshold * matches[0].distance
            )

            # Calculate similarity based on good matches relative to keypoints
            max_possible_matches = min(
                len(features1["keypoints"]), len(features2["keypoints"])
            )
            
            # Return a higher similarity score for very close matches
            similarity = (
                good_matches_count / max_possible_matches
                if max_possible_matches > 0
                else 0.0
            )
            
            # Boost similarity for very close matches (helps with grouping)
            if similarity > 0.8:
                similarity = min(1.0, similarity * 1.1)  # Boost by 10% but cap at 1.0
                
            return similarity
            
        except Exception as e:
            print(f"Error calculating feature similarity: {str(e)}")
            return 0.0

    def group_screenshots(self) -> None:
        """Group screenshots based on similarity."""
        print("Grouping screenshots by similarity...")

        # Initialize all screenshots as ungrouped
        ungrouped = list(range(len(self.screenshots)))
        self.groups = []

        # Debugging: Print the similarity threshold and sample of similarity scores
        threshold = self.config["min_similarity_for_group"]
        print(f"Using similarity threshold: {threshold}")
        
        # Sample some similarity scores to verify they're being calculated correctly
        if len(self.screenshots) >= 2:
            sample_pairs = [
                (i, j) for i in range(min(5, len(self.screenshots))) 
                for j in range(i+1, min(6, len(self.screenshots)))
            ]
            for i, j in sample_pairs:
                sim_score = self.similarity_matrix[i, j]
                print(f"Similarity between {self.screenshots[i]['domain']} and {self.screenshots[j]['domain']}: {sim_score:.4f}")
        
        # Lower the effective threshold slightly for debugging
        # effective_threshold = max(0.5, threshold - 0.1)  # Uncomment to test with a slightly lower threshold
        effective_threshold = threshold
        
        while ungrouped:
            # Create a new group starting with the first ungrouped screenshot
            group_seed = ungrouped.pop(0)
            group = [group_seed]

            # Find all similar screenshots to add to this group
            i = 0
            while i < len(ungrouped):
                screenshot_idx = ungrouped[i]

                # Check if this screenshot is similar enough to any in the current group
                # Use the highest similarity score with any group member
                max_similarity = max(
                    self.similarity_matrix[group_member, screenshot_idx]
                    for group_member in group
                )
                
                # Debug the highest similarity for this candidate
                if max_similarity > 0.5:  # Only print scores that are somewhat high
                    seed_domain = self.screenshots[group[0]]['domain']
                    candidate_domain = self.screenshots[screenshot_idx]['domain']
                    print(f"Candidate: {candidate_domain}, Similarity to group seed {seed_domain}: {max_similarity:.4f}")
                
                if max_similarity >= effective_threshold:
                    group.append(screenshot_idx)
                    ungrouped.pop(i)
                else:
                    i += 1

            # Add the new group to our list
            self.groups.append(
                {
                    "group_id": len(self.groups) + 1,
                    "screenshots": [
                        {
                            "index": idx,
                            "path": self.screenshots[idx]["path"],
                            "domain": self.screenshots[idx]["domain"],
                            "filename": self.screenshots[idx]["filename"],
                        }
                        for idx in group
                    ],
                    "count": len(group),
                    "domains": [self.screenshots[idx]["domain"] for idx in group],
                }
            )

        print(f"Grouped screenshots into {len(self.groups)} visual similarity groups.")

    def generate_output(self, output_dir: str) -> None:
        """
        Generate output files based on the analysis.

        Args:
            output_dir: Directory to save output files
        """
        print(f"Generating output files in {output_dir}...")

        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)

        # Generate report JSON
        if self.config["generate_report"]:
            report = {
                "timestamp": datetime.now().isoformat(),
                "total_screenshots": len(self.screenshots),
                "total_groups": len(self.groups),
                "groups": [
                    {
                        "group_id": group["group_id"],
                        "count": group["count"],
                        "domains": group["domains"],
                        "screenshots": [ss["filename"] for ss in group["screenshots"]],
                    }
                    for group in self.groups
                ],
            }

            with open(
                os.path.join(output_dir, "screenshot-analysis-report.json"), "w"
            ) as f:
                json.dump(report, f, indent=2)

            print("Generated analysis report JSON.")

        # Generate group composite images
        if self.config["generate_grouped_images"]:
            # Create directories for grouped screenshots
            groups_dir = os.path.join(output_dir, "groups")
            os.makedirs(groups_dir, exist_ok=True)

            # For each group, copy screenshots to respective group folder
            for group in self.groups:
                group_dir = os.path.join(groups_dir, f"group_{group['group_id']}")
                os.makedirs(group_dir, exist_ok=True)

                # Copy each screenshot in the group
                for screenshot in group["screenshots"]:
                    shutil.copy2(
                        screenshot["path"],
                        os.path.join(group_dir, screenshot["filename"]),
                    )

                # Generate a composite image for the group if it has multiple screenshots
                if group["count"] > 1:
                    self.generate_composite_image(group, group_dir)

            print("Generated grouped screenshots.")

        print("Output generation complete.")

    def generate_composite_image(self, group: Dict, output_dir: str) -> None:
        """
        Generate a composite image for a group of screenshots.

        Args:
            group: Group object
            output_dir: Directory to save composite image
        """
        try:
            # Determine grid size based on number of screenshots
            count = min(group["count"], 4)  # Limit to 4 screenshots in composite
            grid_size = int(np.ceil(np.sqrt(count)))

            # Calculate composite dimensions
            composite_width = self.config["target_width"] * grid_size
            composite_height = self.config["target_height"] * int(
                np.ceil(count / grid_size)
            )

            # Create a white background image
            composite = (
                np.ones((composite_height, composite_width, 3), dtype=np.uint8) * 255
            )

            # Add screenshot thumbnails to the composite
            for i, screenshot_info in enumerate(group["screenshots"][:count]):
                row = i // grid_size
                col = i % grid_size

                # Get the image
                img = self.screenshots[screenshot_info["index"]]["image"]

                # Calculate position
                y_start = row * self.config["target_height"]
                y_end = y_start + self.config["target_height"]
                x_start = col * self.config["target_width"]
                x_end = x_start + self.config["target_width"]

                # Ensure we don't go out of bounds
                if y_end <= composite_height and x_end <= composite_width:
                    composite[y_start:y_end, x_start:x_end] = img

            # Save the composite image
            cv2.imwrite(
                os.path.join(output_dir, f"group_{group['group_id']}_composite.png"),
                composite,
            )

        except Exception as e:
            print(
                f"Error generating composite image for group {group['group_id']}: {str(e)}"
            )

    def run(self, input_dir: str, output_dir: str) -> Dict:
        """
        Run the complete analysis pipeline.

        Args:
            input_dir: Directory containing screenshots
            output_dir: Directory to save output files

        Returns:
            Analysis results
        """
        # Load screenshots
        self.load_screenshots(input_dir)

        if not self.screenshots:
            print("No valid screenshots found. Exiting.")
            return {"error": "No valid screenshots found"}

        # Analyze similarities
        self.analyze_similarity()

        # Group screenshots
        self.group_screenshots()

        # Generate output
        self.generate_output(output_dir)

        # Return analysis results
        return {
            "total_screenshots": len(self.screenshots),
            "total_groups": len(self.groups),
            "groups": self.groups,
        }


def enhance_reports_with_screenshot_analysis(
    screenshot_dir: str, output_dir: str, domain_data: List[Dict]
) -> Dict:
    """
    Integration function to connect screenshot analysis with abuse report generation.

    Args:
        screenshot_dir: Directory containing screenshots
        output_dir: Directory to save analysis output
        domain_data: List of domain investigation data

    Returns:
        Enhanced data with screenshot grouping info
    """
    print("Starting screenshot analysis to enhance reports...")

    # Run screenshot analysis
    analyzer = ScreenshotAnalyzer()
    analysis_results = analyzer.run(screenshot_dir, output_dir)

    if "error" in analysis_results:
        return {"error": analysis_results["error"]}

    print("Enhancing domain data with screenshot analysis...")

    # Create a map of domain to screenshot group
    domain_to_group_map = {}

    for group in analysis_results["groups"]:
        for domain in group["domains"]:
            domain_to_group_map[domain] = {
                "group_id": group["group_id"],
                "total_domains_in_group": group["count"],
                "similar_domains": [d for d in group["domains"] if d != domain],
            }

    # Enhance domain data with screenshot group information
    enhanced_data = []
    for domain_info in domain_data:
        domain_name = domain_info.get("domain")
        group_info = domain_to_group_map.get(domain_name)

        enhanced_domain = {
            **domain_info,
            "screenshot_analysis": group_info
            or {
                "group_id": None,
                "message": "No screenshot found or domain not part of any visual similarity group",
            },
        }

        enhanced_data.append(enhanced_domain)

    # Generate enhanced abuse reports that include screenshot evidence
    report_data = {
        "analysis_date": datetime.now().isoformat(),
        "total_domains": len(domain_data),
        "total_screenshots": analysis_results["total_screenshots"],
        "visual_groups": analysis_results["total_groups"],
        "enhanced_domain_data": enhanced_data,
        "visual_similarity_groups": [
            {
                "group_id": group["group_id"],
                "domains": group["domains"],
                "count": group["count"],
                "composite_path": f"groups/group_{group['group_id']}/group_{group['group_id']}_composite.png",
            }
            for group in analysis_results["groups"]
        ],
    }

    # Save the enhanced report data
    os.makedirs(output_dir, exist_ok=True)
    with open(os.path.join(output_dir, "enhanced-abuse-report-data.json"), "w") as f:
        json.dump(report_data, f, indent=2)

    print("Enhanced abuse report data generated successfully.")
    return report_data


def analyze_novelty_patterns(investigations: List[Dict], enhanced_data: Dict) -> Dict:
    """
    Analyze novelty patterns in the campaign.

    Args:
        investigations: List of domain investigation data
        enhanced_data: Data enhanced with screenshot analysis

    Returns:
        Novelty analysis results
    """
    # Sort domains by creation date (newest first)
    sorted_domains = sorted(
        investigations,
        key=lambda x: x.get("whois_info", {}).get("creation_date", ""),
        reverse=True,
    )

    # Group domains by registration date
    domains_by_date = {}
    for domain in sorted_domains:
        creation_date = domain.get("whois_info", {}).get("creation_date", "")
        if not creation_date:
            continue

        # Format to just the date part
        date_only = creation_date.split("T")[0]

        if date_only not in domains_by_date:
            domains_by_date[date_only] = []

        domains_by_date[date_only].append(domain.get("domain"))

    # Find domains registered in the last 7 days
    from datetime import datetime, timedelta

    recent_cutoff = (datetime.now() - timedelta(days=7)).isoformat().split("T")[0]

    recent_domains = []
    for date, domains in domains_by_date.items():
        if date >= recent_cutoff:
            recent_domains.extend(domains)

    # Detect infrastructure changes over time
    timeline = []
    sorted_dates = sorted(domains_by_date.keys())

    for date in sorted_dates:
        date_domains = [
            d
            for d in investigations
            if d.get("whois_info", {}).get("creation_date", "").startswith(date)
        ]

        # Extract common patterns for this date
        nameservers = set()
        cnameRecords = set()

        for domain in date_domains:
            ns = domain.get("whois_info", {}).get("nameservers", [])
            if ns:
                nameservers.update([n.split(".")[0] for n in ns if n])

            cname = domain.get("dns_records", {}).get("CNAME", [])
            if cname:
                cnameRecords.update(cname)

        timeline.append(
            {
                "date": date,
                "domains_count": len(date_domains),
                "domains": domains_by_date[date],
                "infrastructure": {
                    "nameserver_patterns": list(nameservers),
                    "cname_records": list(cnameRecords),
                },
            }
        )

    # Identify novelty patterns
    visual_group_evolution = {}

    # Map registration dates to visual groups
    for domain_info in enhanced_data.get("enhanced_domain_data", []):
        domain = domain_info.get("domain")
        group_id = domain_info.get("screenshot_analysis", {}).get("group_id")

        if not group_id:
            continue

        # Find creation date
        for inv in investigations:
            if inv.get("domain") == domain:
                creation_date = (
                    inv.get("whois_info", {}).get("creation_date", "").split("T")[0]
                )

                if group_id not in visual_group_evolution:
                    visual_group_evolution[group_id] = []

                visual_group_evolution[group_id].append(
                    {"domain": domain, "date": creation_date}
                )
                break

    # Sort each group's domains by date
    for group_id, domains in visual_group_evolution.items():
        visual_group_evolution[group_id] = sorted(
            domains, key=lambda x: x.get("date", "")
        )

    return {
        "newest_domains": recent_domains,
        "registration_timeline": timeline,
        "visual_group_evolution": visual_group_evolution,
    }


def main():
    """CLI interface for running the screenshot analyzer."""
    import argparse

    parser = argparse.ArgumentParser(description="Screenshot Similarity Analyzer")
    parser.add_argument(
        "--screenshots", required=True, help="Directory containing screenshots"
    )
    parser.add_argument("--output", required=True, help="Directory for output")
    parser.add_argument(
        "--investigations", help="Directory containing investigation JSON files"
    )

    args = parser.parse_args()

    # Check if screenshot directory exists
    if not os.path.exists(args.screenshots):
        print(f"Screenshot directory does not exist: {args.screenshots}")
        return 1

    # Run the analyzer
    analyzer = ScreenshotAnalyzer()
    results = analyzer.run(args.screenshots, args.output)

    # If investigations directory is provided, enhance reports
    if args.investigations and os.path.exists(args.investigations):
        try:
            from abuse_report_generator import load_investigation_files

            investigations = load_investigation_files(args.investigations)
            enhanced_data = enhance_reports_with_screenshot_analysis(
                args.screenshots, os.path.join(args.output, "enhanced"), investigations
            )

            # Generate novelty analysis
            novelty = analyze_novelty_patterns(investigations, enhanced_data)
            with open(os.path.join(args.output, "novelty-analysis.json"), "w") as f:
                json.dump(novelty, f, indent=2)

            print("Novelty analysis complete.")
        except Exception as e:
            print(f"Error enhancing reports with screenshot data: {str(e)}")

    print(
        f"Analysis complete. Found {results['total_groups']} visual similarity groups across {results['total_screenshots']} screenshots."
    )
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
