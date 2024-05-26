#!/bin/bash

# Define variables
WEB_ROOT="/var/www/html"
LOG_FILE="/var/log/apache2/report_log.json"
LOG_DIR=$(dirname "$LOG_FILE")

# Create necessary directories and set permissions
echo "Creating necessary directories..."
sudo mkdir -p "$LOG_DIR"
sudo chmod 755 "$LOG_DIR"

# Create the log file if it doesn't exist and set permissions
if [ ! -f "$LOG_FILE" ]; then
    echo "Creating log file..."
    sudo touch "$LOG_FILE"
fi
sudo chmod 666 "$LOG_FILE"

# Move PHP and CSS files to web root
echo "Moving PHP and CSS files to $WEB_ROOT..."
sudo mv report.php "$WEB_ROOT/"
sudo mv view_reports.php "$WEB_ROOT/"
sudo mv styles.css "$WEB_ROOT/"

# Print completion message
echo "Setup completed successfully."
