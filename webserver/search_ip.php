<?php
if (isset($_GET['ip'])) {
    $ip = $_GET['ip'];
    $api_url = "http://ipinfo.io/{$ip}/json";

    $response = file_get_contents($api_url);
    $data = json_decode($response, true);

    if (isset($data['error'])) {
        echo json_encode(['error' => 'Invalid IP address or could not fetch data.']);
    } else {
        $result = [
            'ip' => $data['ip'] ?? 'N/A',
            'country' => $data['country'] ?? 'N/A',
            'country_code' => $data['country_code'] ?? 'N/A',
            'region' => $data['region'] ?? 'N/A',
            'city' => $data['city'] ?? 'N/A'
        ];
        echo json_encode($result);
    }
} else {
    echo json_encode(['error' => 'IP address not provided.']);
}
?>
