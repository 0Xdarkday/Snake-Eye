<?php
// Path to the log file
$log_file = '/var/log/apache2/report_log.json';

if (file_exists($log_file)) {
    if (is_writable($log_file)) {
        $file = fopen($log_file, "w");
        if ($file) {
            fclose($file);
            header("Location: view_reports.php");
            exit;
        } else {
            $error_message = "Failed to open the report log file.";
            error_log($error_message);
            echo $error_message;
        }
    } else {
        $error_message = "The report log file is not writable.";
        error_log($error_message);
        echo $error_message;
    }
} else {
    $error_message = "No reports available to delete.";
    error_log($error_message);
    echo $error_message;
}
?>
