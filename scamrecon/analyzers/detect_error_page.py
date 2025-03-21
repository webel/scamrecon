import logging
import os
import shutil

import cv2
import numpy as np

# Set up logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class ChromeErrorScreenshotSorter:
    def __init__(self, source_dir, dead_dir):
        """
        Initialize the sorter with source and destination directories.

        Args:
            source_dir (str): Directory containing screenshots to analyze
            dead_dir (str): Directory to move "dead" (error) screenshots to
        """
        self.source_dir = source_dir
        self.dead_dir = dead_dir

        # Create dead directory if it doesn't exist
        if not os.path.exists(dead_dir):
            os.makedirs(dead_dir)
            logger.info(f"Created dead directory: {dead_dir}")

        # The specific dark background color in Chrome error pages
        # RGB value approximately (32, 32, 37) or hex #202025
        self.error_dark_bg_color = np.array([32, 32, 37])
        # RGB value approximately #fefffe or hex #FEFFFE
        self.error_light_bg_color = np.array([254, 255, 254])
        self.color_threshold = 5  # Allow small variations in color

    def is_chrome_error_page(self, img_path):
        """
        Check if the image is a Chrome error page by detecting the specific background color.
        Match towards known dark and light mode.
        """
        try:
            # Read the image
            img = cv2.imread(img_path)
            if img is None:
                logger.warning(f"Could not read image: {img_path}")
                return False

            # Convert from BGR to RGB
            img_rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)

            # Get dimensions
            height, width, _ = img.shape

            # Sample points to check for the background color
            # Check several regions instead of the entire image for efficiency
            sample_regions = [
                (width // 2, height // 2),  # Center
                (width // 4, height // 4),  # Top-left quadrant
                (3 * width // 4, height // 4),  # Top-right quadrant
                (width // 4, 3 * height // 4),  # Bottom-left quadrant
                (3 * width // 4, 3 * height // 4),  # Bottom-right quadrant
            ]

            # Count how many sample points match the error page color
            matches = 0
            for x, y in sample_regions:
                pixel_color = img_rgb[y, x]
                # Check if the color is close to our target color
                if np.all(
                    np.abs(pixel_color - self.error_dark_bg_color)
                    <= self.color_threshold
                ):
                    matches += 1
                if np.all(
                    np.abs(pixel_color - self.error_light_bg_color)
                    <= self.color_threshold
                ):
                    matches += 1

            # If majority of samples match, it's likely an error page
            is_error = matches >= 3

            logger.debug(
                f"Image {os.path.basename(img_path)}: matched {matches}/5 sample points"
            )
            return is_error

        except Exception as e:
            logger.error(f"Error processing {img_path}: {e}")
            return False

    def process_directory(self):
        """Process all images in the source directory and move error screenshots to dead directory"""
        # Get all image files
        image_extensions = (".png", ".jpg", ".jpeg", ".bmp", ".tiff")
        image_files = [
            f
            for f in os.listdir(self.source_dir)
            if os.path.isfile(os.path.join(self.source_dir, f))
            and f.lower().endswith(image_extensions)
        ]

        logger.info(f"Found {len(image_files)} image files to process")

        moved_count = 0
        for img_file in image_files:
            img_path = os.path.join(self.source_dir, img_file)
            is_error = self.is_chrome_error_page(img_path)

            if is_error:
                dest_path = os.path.join(self.dead_dir, img_file)
                shutil.move(img_path, dest_path)
                moved_count += 1
                logger.info(f"Moved error screenshot {img_file} to dead folder")
            else:
                logger.debug(f"Kept {img_file}")

        logger.info(
            f"Finished processing. Moved {moved_count} error screenshots to {self.dead_dir}"
        )
        return moved_count


# Example usage
if __name__ == "__main__":
    # Change these paths to match your environment
    SOURCE_DIR = "19_03_2025_screenshots"
    DEAD_DIR = "19_03_2025_screenshots_dead"

    # Create and run the sorter
    sorter = ChromeErrorScreenshotSorter(SOURCE_DIR, DEAD_DIR)
    moved_count = sorter.process_directory()
    print(f"Moved {moved_count} error screenshots to {DEAD_DIR}")
