<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Security Reports</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <div class="container">
        <h1>Network Security Reports</h1>
        <table>
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Attack Type</th>
                    <th>Source IP</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
                <?php
                $log_file = '/var/log/apache2/report_log.json';
                if (file_exists($log_file)) {
                    $reports = json_decode(file_get_contents($log_file), true);
                    foreach ($reports as $report) {
                        echo "<tr>";
                        echo "<td>" . date("Y-m-d H:i:s") . "</td>";
                        echo "<td>" . htmlspecialchars($report['attack_type']) . "</td>";
                        echo "<td>" . htmlspecialchars($report['src_ip']) . "</td>";
                        echo "<td>" . htmlspecialchars(json_encode($report['details'])) . "</td>";
                        echo "</tr>";
                    }
                } else {
                    echo "<tr><td colspan='4'>No reports available.</td></tr>";
                }
                ?>
            </tbody>
        </table>
    </div>
</body>
</html>
