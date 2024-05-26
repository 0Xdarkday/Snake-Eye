<?php
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $data = file_get_contents("php://input");
    $decoded_data = base64_decode($data);
    $json_data = json_decode($decoded_data, true);

    $log_file = '/var/log/apache2/report_log.json';
    
    // Ensure the log file exists
    if (!file_exists($log_file)) {
        file_put_contents($log_file, json_encode([]));
    }

    $current_data = json_decode(file_get_contents($log_file), true);
    $current_data[] = $json_data;
    file_put_contents($log_file, json_encode($current_data, JSON_PRETTY_PRINT));
    
    echo "Report received and logged.";
} else {
    echo "No data received.";
}
?>
