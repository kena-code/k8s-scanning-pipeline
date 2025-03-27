import json
import os

# Map images to their JSON report files
image_reports = {
    "httpd:2.4.49": "trivy-report-httpd.json",
    "nginx:1.15": "trivy-report-nginx.json",
    "mysql:5.5": "trivy-report-mysql.json",
    "wordpress:4.9.8": "trivy-report-wordpress.json",
    "vulnerables/web-dvwa": "trivy-report-web-dvwa.json",
    "bkimminich/juice-shop": "trivy-report-juice-shop.json"
}

k8s_report = "trivy-report-k8s.json"

# Function to count vulnerabilities from image reports
def count_vulnerabilities(report_file):
    if not os.path.exists(report_file):
        print(f"Report file {report_file} not found")
        return {"HIGH": 0, "CRITICAL": 0}
    with open(report_file, 'r') as f:
        data = json.load(f)
    vuln_counts = {"HIGH": 0, "CRITICAL": 0}
    if isinstance(data, list) and data:
        for result in data:
            if "Vulnerabilities" in result:
                for vuln in result["Vulnerabilities"]:
                    severity = vuln.get("Severity")
                    if severity in vuln_counts:
                        vuln_counts[severity] += 1
    return vuln_counts

# Function to analyze Kubernetes misconfigurations
def analyze_k8s_misconfigs(report_file):
    if not os.path.exists(report_file):
        print(f"Kubernetes report {report_file} not found")
        return {}
    with open(report_file, 'r') as f:
        data = json.load(f)
    severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for result in data.get("Results", []):
        for misconfig in result.get("Misconfigurations", []):
            severity = misconfig.get("Severity")
            if severity in severity_counts:
                severity_counts[severity] += 1
    return severity_counts

# Main analysis with scan times from a file
print("Container Image Statistics:")
total_high = 0
total_critical = 0
with open("scan_times.txt", "r") as f:
    scan_times = dict(line.strip().split() for line in f)

for image, report_file in image_reports.items():
    vuln_counts = count_vulnerabilities(report_file)
    scan_time = float(scan_times.get(f"{image.replace(':', '_')}_scan_time", 0))
    print(f"{image}: {vuln_counts['HIGH']} HIGH, {vuln_counts['CRITICAL']} CRITICAL, Scan Time: {scan_time:.2f} seconds")
    total_high += vuln_counts["HIGH"]
    total_critical += vuln_counts["CRITICAL"]

print(f"Total: {total_high} HIGH, {total_critical} CRITICAL")

print("\nKubernetes Config Statistics:")
k8s_counts = analyze_k8s_misconfigs(k8s_report)
k8s_scan_time = float(scan_times.get("k8s_scan_time", 0))
print(f"Kubernetes Configs: {k8s_counts['LOW']} LOW, {k8s_counts['MEDIUM']} MEDIUM, {k8s_counts['HIGH']} HIGH, {k8s_counts['CRITICAL']} CRITICAL, Scan Time: {k8s_scan_time:.2f} seconds")
