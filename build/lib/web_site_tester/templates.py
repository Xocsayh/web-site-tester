HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Web Site Tester Report</title>
  <style>
    body { font-family: Arial, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 24px; }
    .wrap { max-width: 1100px; margin: 0 auto; }
    .card { background: #111827; border: 1px solid #1f2937; border-radius: 16px; padding: 20px; margin-bottom: 18px; }
    .score { font-size: 42px; font-weight: 700; }
    .muted { color: #94a3b8; }
    .sev-low { color: #facc15; }
    .sev-medium { color: #fb923c; }
    .sev-high { color: #f87171; }
    .ok { color: #4ade80; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 12px; border-bottom: 1px solid #1f2937; text-align: left; }
    code { background: #0b1220; padding: 2px 6px; border-radius: 6px; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>Web Site Tester Report</h1>
      <p class="muted">Target: {{target}}</p>
      <div class="score">{{score}}/100</div>
      <p>Status: <strong>{{level}}</strong></p>
      <p>Message: <strong>{{message}}</strong></p>
    </div>

    <div class="card">
      <h2>Technology Hints</h2>
      <ul>
      {{tech_items}}
      </ul>
    </div>

    <div class="card">
      <h2>Findings</h2>
      <table>
        <thead>
          <tr>
            <th>Title</th>
            <th>Severity</th>
            <th>Penalty</th>
            <th>Detail</th>
          </tr>
        </thead>
        <tbody>
          {{finding_rows}}
        </tbody>
      </table>
    </div>
  </div>
</body>
</html>
"""