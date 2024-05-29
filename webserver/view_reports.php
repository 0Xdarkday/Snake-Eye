<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Security Reports</title>
    <link rel="stylesheet" href="styles.css">
    <style>
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #fff;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        .header, .actions {
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
            color: red; /* Set attack type text color to red */
        }
        .ip-search {
            margin-top: 20px;
            display: flex;
            gap: 10px;
        }
        .ip-result {
            margin-top: 20px;
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
        }
    </style>
    <script>
        function searchIP() {
            var ip = document.getElementById('ip-input').value;
            if (ip) {
                fetch('search_ip.php?ip=' + ip)
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        alert(data.error);
                    } else {
                        var resultDiv = document.getElementById('ip-result');
                        resultDiv.innerHTML = `
                            <h3>IP Information</h3>
                            <p><strong>IP:</strong> ${data.ip}</p>
                            <p><strong>Country:</strong> ${data.country}</p>
                            <p><strong>Country Code:</strong> ${data.country_code}</p>
                            <p><strong>Region:</strong> ${data.region}</p>
                            <p><strong>City:</strong> ${data.city}</p>
                        `;
                    }
                })
                .catch(error => {
                    alert('Error fetching IP information: ' + error);
                });
            } else {
                alert('Please enter an IP address');
            }
        }
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Network Security Reports</h1>
            <div class="actions">
                <button class="btn" onclick="location.reload()">Refresh</button>
                <form action="delete_reports.php" method="post" style="display:inline;">
                    <button class="btn" type="submit">Delete Reports</button>
                </form>
            </div>
        </div>

        <div class="ip-search">
            <input type="text" id="ip-input" placeholder="Enter IP address">
            <button class="btn" onclick="searchIP()">Search IP</button>
        </div>
        <div id="ip-result" class="ip-result"></div>

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
