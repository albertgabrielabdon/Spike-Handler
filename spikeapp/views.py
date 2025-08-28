from django.views import View
from django.shortcuts import render
import requests
import pandas as pd
from datetime import datetime
import os

class SpikeHandlerView(View):
    template_name = "spike_handler.html"

    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
    ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
    ABUSEIPDB_HEADERS = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }

    def get(self, request):
        return render(request, self.template_name)

    def post(self, request):
        ip_input = request.POST.get("ip_addresses", "")
        ticket_no = request.POST.get("ticket_no", "Ticket No.")
        related_website = request.POST.get("related_website", "smcinema.com")
        ojt_name = request.POST.get("ojt_name", "OJT Name")

        ayen_request_1_input = = ip_input.replace(" ", ",").replace(",,", ",")
        ip_list = [ip.strip() for ip in ayen_request_1_input.split(",") if ip.strip()]

        results = []
        non_malicious = []
        malicious = []
        for_review = []
        today = datetime.now().strftime("%m/%d/%Y")

        for ip in ip_list:
            try:
                response = requests.get(
                    self.ABUSEIPDB_URL,
                    headers=self.ABUSEIPDB_HEADERS,
                    params={"ipAddress": ip, "maxAgeInDays": 120, "verbose": True}
                )
                data = response.json().get("data", {})

                confidence = data.get("abuseConfidenceScore", 0)
                reports = data.get("totalReports", 0)
                isp = data.get("isp") or "N/A"
                country = data.get("countryCode") or "N/A"

                results.append({
                    "IP_Address": ip,
                    "Confidence_Score": confidence,
                    "Reports": reports,
                    "ISP": isp,
                    "Country": country
                })

                if confidence == 0 and reports == 0:
                    non_malicious.append(ip)
                elif confidence > 0:
                    malicious.append(ip)
                elif confidence == 0 and reports > 0:
                    for_review.append(ip)

            except Exception as e:
                results.append({
                    "IP_Address": ip,
                    "Confidence_Score": 0,
                    "Reports": str(e),
                    "ISP": "N/A",
                    "Country": "N/A"
                })

        ticket_resolution = ""
        if non_malicious:
            ticket_resolution += "NON-MALICIOUS: " + ",".join(non_malicious) + "\n"
        if malicious:
            ticket_resolution += "MALICIOUS: " + ",".join(malicious) + "\n"
        if for_review:
            ticket_resolution += "FOR REVIEW: " + ",".join(for_review) + "\n"


        def create_log(ip, status):
            return {
                "IP": ip,
                "Date": today,
                "Source": "Cloudflare WAF",
                "Ticket_No": ticket_no,
                "Event": f"Spike in security events for {related_website}",
                "Details": f"CF detected {status} history from IP {ip}. The IP was already blocked in CF if applicable. Done adding to IP blacklist.",
                "Resolver": ojt_name
            }

        incident_logs = []
        for ip in non_malicious:
            incident_logs.append(create_log(ip, "NON-MALICIOUS"))
        for ip in malicious:
            incident_logs.append(create_log(ip, "MALICIOUS"))
        for ip in for_review:
            incident_logs.append(create_log(ip, "FOR REVIEW"))


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
                ojt_name,
                related_website,
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
        df_resolution.rename(columns={"Column A": "Column_A", "Column B": "Column_B"}, inplace=True)


        context = {
            "ip_input": ip_input,
            "related_website": related_website,
            "ticket_no": ticket_no,
            "ojt_name": ojt_name,
            "output": pd.DataFrame(results).to_dict(orient="records"),
            "ticket_resolution": ticket_resolution.strip(),
            "incident_log": incident_logs,
            "df_resolution": df_resolution.to_dict(orient="records")
        }

        return render(request, self.template_name, context)

