# report.py
# Simple Report Generation

import json
import csv
from datetime import datetime

class ReportGenerator:
    def __init__(self):
        self.timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    
    def generate_text_summary(self, results, score_results):
        """Generate simple text summary for console output"""
        if not results:
            return "No checks were performed."
        
        summary = []
        summary.append("\n" + "="*60)
        summary.append("AWS SECURITY AUDIT - DETAILED FINDINGS")
        summary.append("="*60)
        
        for result in results:
            if result['status'] == 'PASS':
                icon = '✅'
            elif result['status'] == 'FAIL':
                icon = '❌'
            elif result['status'] == 'WARN':
                icon = '⚠️ '
            else:
                icon = '🔧'
            
            summary.append(f"\n{icon} {result['check_id']}: {result['title']}")
            summary.append(f"   Status: {result['status']} | Severity: {result['severity']}")
            summary.append(f"   {result['description']}")
            
            if result['status'] != 'PASS':
                summary.append(f"   🔧 Remediation: {result['remediation']}")
        
        return "\n".join(summary)
    
    def generate_json_report(self, results, score_results, filename=None):
        """Generate JSON report"""
        if not filename:
            filename = f"aws_security_audit_{self.timestamp}.json"
        
        report = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "tool_version": "1.0.0",
                "report_type": "AWS Security Audit"
            },
            "summary": score_results,
            "detailed_results": results
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"📊 JSON report saved to: {filename}")
        return report
    
    def generate_csv_report(self, results, filename=None):
        """Generate CSV report"""
        if not filename:
            filename = f"aws_security_audit_{self.timestamp}.csv"
        
        if not results:
            print("⚠️  No results to save as CSV")
            return
        
        # Define CSV columns
        fieldnames = [
            'check_id',
            'status',
            'severity',
            'title',
            'description',
            'remediation',
            'timestamp'
        ]
        
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for result in results:
                # Add timestamp to each row
                row_data = result.copy()
                row_data['timestamp'] = datetime.now().isoformat()
                writer.writerow(row_data)
        
        print(f"📈 CSV report saved to: {filename}")
    
    def generate_html_report(self, results, score_results, filename=None):
        """Generate HTML report"""
        if not filename:
            filename = f"aws_security_audit_{self.timestamp}.html"
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>AWS Security Audit Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
                .score {{ font-size: 48px; font-weight: bold; margin: 20px 0; }}
                .critical {{ color: #e74c3c; }}
                .high {{ color: #e67e22; }}
                .medium {{ color: #f1c40f; }}
                .low {{ color: #3498db; }}
                .passed {{ color: #27ae60; }}
                .failed {{ color: #e74c3c; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th {{ background: #ecf0f1; padding: 10px; text-align: left; }}
                td {{ padding: 10px; border-bottom: 1px solid #ddd; }}
                tr:hover {{ background: #f5f5f5; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🔒 AWS Security Audit Report</h1>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <h2>Executive Summary</h2>
            <div class="score {score_results.get('risk_level', '').lower()}">
                Risk Score: {score_results.get('overall_risk_score', 0)}/100 {score_results.get('risk_emoji', '')}
            </div>
            
            <table>
                <tr>
                    <th>Metric</th>
                    <th>Value</th>
                </tr>
                <tr>
                    <td>Risk Level</td>
                    <td class="{score_results.get('risk_level', '').lower()}">{score_results.get('risk_level', 'UNKNOWN')}</td>
                </tr>
                <tr>
                    <td>Total Checks</td>
                    <td>{score_results.get('total_checks', 0)}</td>
                </tr>
                <tr>
                    <td>Passed Checks</td>
                    <td class="passed">{score_results.get('passed_checks', 0)}</td>
                </tr>
                <tr>
                    <td>Failed Checks</td>
                    <td class="failed">{score_results.get('failed_checks', 0)}</td>
                </tr>
            </table>
            
            <h2>Detailed Findings</h2>
            <table>
                <tr>
                    <th>Check ID</th>
                    <th>Title</th>
                    <th>Status</th>
                    <th>Severity</th>
                    <th>Description</th>
                </tr>
        """
        
        # Add each check result
        for result in results:
            html += f"""
                <tr>
                    <td><strong>{result['check_id']}</strong></td>
                    <td>{result['title']}</td>
                    <td class="{result['status'].lower()}">{result['status']}</td>
                    <td class="{result['severity'].lower()}">{result['severity']}</td>
                    <td>{result['description']}</td>
                </tr>
            """
        
        html += """
            </table>
            
            <div style="margin-top: 40px; color: #7f8c8d; font-size: 12px;">
                <hr>
                <p>Report generated by AWS Security Scanner v1.0</p>
            </div>
        </body>
        </html>
        """
        
        with open(filename, 'w') as f:
            f.write(html)
        
        print(f"🌐 HTML report saved to: {filename}")