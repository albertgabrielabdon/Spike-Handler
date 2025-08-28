import requests
import pandas as pd
from datetime import datetime

# -------------------- AbuseIPDB Setup --------------------
ABUSEIPDB_API_KEY = "9b908d8bf0d34363138c11a8c88299f31b6f44f72e21e160ae2012d64513a73a23a20bc9a689e778"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSEIPDB_HEADERS = {
    "Key": ABUSEIPDB_API_KEY,
    "Accept": "application/json"
}

# -------------------- Input IPs --------------------
raw_input_ips = input("Enter IP addresses (comma-separated): ")
ip_list = [ip.strip() for ip in raw_input_ips.split(",") if ip.strip()]

# -------------------- Collect AbuseIPDB Results (with ISP and Country) --------------------
results = []

for ip in ip_list:
    try:
        response = requests.get(
            ABUSEIPDB_URL,
            headers=ABUSEIPDB_HEADERS,
            params={"ipAddress": ip, "maxAgeInDays": 120, "verbose": True}
        )
        data = response.json().get("data", {})

        confidence = data.get("abuseConfidenceScore", 0)
        reports = data.get("totalReports", 0)
        isp = data.get("isp") or "N/A"
        country = data.get("countryCode") or "N/A"

        results.append({
            "IP Address": ip,
            "Confidence Score": confidence,
            "Reports": reports,
            "ISP": isp,
            "Country": country
        })
        
    except Exception as e:
        results.append({
            "IP Address": ip,
            "Confidence Score": 0,
            "Reports": str(e),
            "ISP": "N/A",
            "Country": "N/A"
        })
        print(f"\nError fetching {ip}: {e}")

df_abuse = pd.DataFrame(results, columns=["IP Address", "Confidence Score", "Reports", "ISP", "Country"])

# -------------------- Print AbuseIPDB Results --------------------
print("\n📌 AbuseIPDB Results:\n")
print(df_abuse.to_string(index=False))


# -------------------- Categorize IPs --------------------
non_malicious = []
malicious = []
for_review = []

for x, row in df_abuse.iterrows():
    ip = row["IP Address"]
    confidence = int(row["Confidence Score"])
    reports = int(row["Reports"])

    if confidence == 0 and reports == 0:
        non_malicious.append(ip)
    elif confidence > 0:
        malicious.append(ip)
    elif confidence == 0 and reports > 0:
        for_review.append(ip)

# -------------------- Prepare Ticket Resolution --------------------
ticket_resolution = ""
if non_malicious:
    ticket_resolution += "NON-MALICIOUS: " + ",".join(non_malicious) + "\n"
if malicious:
    ticket_resolution += "MALICIOUS: " + ",".join(malicious) + "\n"
if for_review:
    ticket_resolution += "FOR REVIEW: " + ",".join(for_review) + "\n"

# -------------------- Build Google Sheets-style Data for AYEN_Resolution --------------------
today = datetime.now().strftime("%m/%d/%Y")
sheets_data = {
    "Column A": [
        "CloudFlare Alert Detection",
        "Technician",
        "Related Website",
        "Relater User",
        "IP Address",
        "Domain",
        "Severity Rating",
        "Threat Summary",
        "Analysis",
        "Action Taken",
        "Next Action",
        "Recommendation",
        "Screenshots/References",
        "Initial Summary",
        "Update Timeline",
        "SOC Summary"
    ],
    "Column B": [
        "None",
        "OJT",
        "None",
        "N/A",
        ticket_resolution.strip(),
        "None",
        "HIGH",
        "Spike has been detected on the website, which imposed a series of attacks.",
        "Based on filtering CF spiked events, all malicious requests have been blocked by WAF.",
        "None",
        "N/A",
        "No further recommendations",
        "CF Detection:",
        "Spike detected, all requests blocked by WAF. No pending actions.",
        today + " - No pending actions. Ticket closure.",
        "Spike detected, all requests blocked by WAF. No pending actions."
    ]
}

df_resolution = pd.DataFrame(sheets_data)

# -------------------- Prepare AYEN_IPs Incident Log --------------------
incident_logs = []

def create_log(ip, status):
    return [
        ip,
        today,
        "Cloudflare WAF",
        "Ticket No.",
        "Spike in security events for smcinema.com",
        f"CF detected {status} history from IP {ip}. The IP was already blocked in CF if applicable. Done adding to IP blacklist.",
        "OJT Lauren"
    ]

for ip in non_malicious:
    incident_logs.append(create_log(ip, "NON-MALICIOUS"))
for ip in malicious:
    incident_logs.append(create_log(ip, "MALICIOUS"))
for ip in for_review:
    incident_logs.append(create_log(ip, "FOR REVIEW"))

incident_df = pd.DataFrame(
    incident_logs,
    columns=["IP", "Date", "Source", "Ticket No.", "Event", "Details", "Resolver"]
)

# -------------------- Print Outputs --------------------
print("\n📌 Ticket Resolution Summary:\n")
print(ticket_resolution.strip())

print("\n📌 AYEN_IPs formatted output:\n")
print(incident_df.to_string(index=False))

# -------------------- Save CSVs --------------------
save_choice = input("\nDo you want to save the AYEN files? (y/n): ").strip().lower()
if save_choice == "y":
    incident_df.to_csv("AYEN_IPs.csv", index=False, encoding="utf-8-sig")
    df_resolution.to_csv("AYEN_Resolution.csv", index=False, encoding="utf-8-sig")
    print("✅ AYEN_IPs.csv and AYEN_Resolution.csv saved")
