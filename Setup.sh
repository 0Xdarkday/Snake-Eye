#!/bin/bash

# Define variables
WEB_ROOT="/var/www/html"
LOG_FILE="/var/log/apache2/report_log.json"
LOG_DIR=$(dirname "$LOG_FILE")
TOOL_WEB_DIR="webserver"

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

# Move PHP and CSS files from the tool's web directory to web root
echo "Moving PHP and CSS files from $TOOL_WEB_DIR to $WEB_ROOT..."
sudo mv "$TOOL_WEB_DIR/report.php" "$WEB_ROOT/"
sudo mv "$TOOL_WEB_DIR/view_report.php" "$WEB_ROOT/"
sudo mv "$TOOL_WEB_DIR/delete_reports.php" "$WEB_ROOT/"
sudo mv "$TOOL_WEB_DIR/styles.css" "$WEB_ROOT/"

# Set correct permissions for the moved files
echo "Setting permissions for the moved files..."
sudo chmod 644 "$WEB_ROOT/report.php"
sudo chmod 644 "$WEB_ROOT/view_report.php"
sudo chmod 644 "$WEB_ROOT/delete_reports.php"
sudo chmod 644 "$WEB_ROOT/styles.css"

# Print completion message
echo "Setup completed successfully."
