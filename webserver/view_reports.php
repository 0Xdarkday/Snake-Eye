<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Security Reports</title>
    <link rel="stylesheet" href="styles.css">
    <style>
        .container {
            display: flex;
            justify-content: space-between; 
            align-items: center; 
        }
        .btn {
            padding: 10px 20px;
            background-color: #007bff;
            color: #fff;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            transition: background-color 0.3s ease;
        }
        .btn:hover {
            background-color: #0056b3;
        }
        .attack-type {
            color: red; 
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Network Security Reports</h1>
        <div>
            <button class="btn" onclick="location.reload()">Refresh</button>
            <form action="delete_reports.php" method="post">
                <button class="btn" type="submit">Delete Reports</button>
            </form>
        </div>
    </div>
    <div class="container">
        <table>
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Attack Type</th>
                    <th>Source IP</th>
                    <th>Destination IP</th>
                    <th>Protocol</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
                <?php
                $log_file = '/var/log/apache2/report_log.json';
                if (file_exists($log_file)) {
                    $reports = json_decode(file_get_contents($log_file), true);
                    foreach ($reports as $report) {
                        if (isset($report['attack_type'])) {
                            echo "<tr>";
                            echo "<td>" . htmlspecialchars($report['timestamp']) . "</td>";
                            echo "<td class='attack-type'>" . htmlspecialchars($report['attack_type']) . "</td>";  
                            echo "<td>" . htmlspecialchars($report['src_ip']) . "</td>";
                            echo "<td>" . htmlspecialchars($report['dst_ip']) . "</td>";
                            echo "<td>" . htmlspecialchars($report['protocol']) . "</td>";
                            echo "<td>" . htmlspecialchars(json_encode($report['details'])) . "</td>";
                            echo "</tr>";
                        }
                    }
                } else {
                    echo "<tr><td colspan='6'>No reports available.</td></tr>";
                }
                ?>
            </tbody>
        </table>
    </div>
</body>
</html>
