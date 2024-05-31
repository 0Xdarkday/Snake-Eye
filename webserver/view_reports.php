<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Snake-Eye Network Security Reports</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <link rel="stylesheet" href="styles.css">
    <style>
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #fff;
            box-shadow: 0 0 15px rgba(0,0,0,0.2);
            border-radius: 10px;
        }
        .header, .actions {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
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
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        table, th, td {
            border: 1px solid #ddd;
        }
        th, td {
            padding: 12px;
            text-align: left;
        }
        th {
            background-color: #007bff;
            color: #fff;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        tr:hover {
            background-color: #f1f1f1;
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
            <h1>Snake-Eye Network Security Reports</h1>
            <div class="actions">
                <button class="btn" onclick="location.reload()"><i class="fas fa-sync-alt"></i> Refresh</button>
                <form action="delete_reports.php" method="post" style="display:inline;">
                    <button class="btn" type="submit"><i class="fas fa-trash-alt"></i> Delete Reports</button>
                </form>
            </div>
        </div>

        <div class="ip-search">
            <input type="text" id="ip-input" placeholder="Enter IP address">
            <button class="btn" onclick="searchIP()"><i class="fas fa-search"></i> Search IP</button>
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
