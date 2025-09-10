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

    @staticmethod
    def zscaler_check(isp: str) -> bool:
        return isp.strip().lower() == "zscaler, inc."

    def get(self, request):
        return render(request, self.template_name)
    
    def build_xss_resolution(self, ip, ip_links, ojt_name, related_website, ticket_no, confidence, reports, isp):
        today = datetime.now().strftime("%m/%d/%Y")

        if confidence > 0:
            status = f"MALICIOUS: {ip}"
            ip_display = status
            action_taken = "Blocked the IP addresses in Cloudflare using XSOAR"
            next_action = "Perform IP blocking using XSOAR"
            recommendation = "No further recommendations"
            soc_summary = (
                "AWS WAF logs detected a malicious source IP performing a XSS attack on the website. "
                "Blocking of IP is already done."
            )

        elif self.zscaler_check(isp): 
            status = f"NON-MALICIOUS: {ip}"
            ip_display = status
            action_taken = "No blocking done as IP is from Zscaler ISP"
            next_action = "No further actions required"
            recommendation = "No further actions"
            soc_summary = (
                "AWS WAF logs detected XSS attempts, "
                "but IP belongs to Zscaler ISP. No blocking required."
            )

        elif reports == 0 and confidence == 0:
            status = f"NON-MALICIOUS: {ip}"
            ip_display = status
            action_taken = "No blocking done as IP is non-malicious"
            next_action = "No further actions required"
            recommendation = "No further actions"
            soc_summary = (
                "AWS WAF logs detected an IP performing XSS attempts, "
                "but based on reputation the IP is non-malicious. No blocking done."
            )

        else:
            status = f"FOR REVIEW: {ip}"
            ip_display = status
            action_taken = "Pending SOC validation before taking action"
            next_action = "Investigate further with SOC"
            recommendation = "Review required before closure"
            soc_summary = (
                "AWS WAF logs detected an IP performing XSS attempts, "
                "but the IP reputation is inconclusive. SOC review required."
            )

        sheets_data_xss = {
            "Column A": [
                "CF - AWS WAF Alert Detection (XSS)",
                "Technician",
                "Related Website",
                "IP Address",
                "Domain",
                "Severity Rating",
                "Threat Summary",
                "Analysis",
                "Action Taken",
                "Next Action",
                "Recommendation",
                "Screenshots/Reference",
                "Update Timeline",
                "SOC Summary"
            ],
            "Column B": [
                status,
                ojt_name,
                related_website,
                ip_display,
                "SMIC",
                "MEDIUM",
                "AWS WAF logs detected a source IP performing a XSS attack on the website.",
                f"CF Detection:\nIP Reputation:\n{ip_links}",
                action_taken,
                next_action,
                recommendation,
                f"CF Detection:\nIP Reputation:\n{ip_links}",
                today + " - For Manage Engine Ticket Closure",
                soc_summary
            ]
        }

        df_xss = pd.DataFrame(sheets_data_xss)
        df_xss.rename(columns={"Column A": "Column_A", "Column B": "Column_B"}, inplace=True)
        return df_xss

    
    def post(self, request):
        ip_input = request.POST.get("ip_addresses", "")
        ticket_no = request.POST.get("ticket_no", "Ticket No.")
        related_website = request.POST.get("related_website", "smcinema.com")
        ojt_name = request.POST.get("ojt_name", "OJT Name")

        ayen_request_1_input = ip_input.replace(" ", ",").replace(",,", ",")
        ip_list = [ip.strip() for ip in ayen_request_1_input.split(",") if ip.strip()]

        results = []
        non_malicious = []
        malicious = []
        for_review = []
        zscaler_non_malicious = []
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
                if isp == "Zscaler, Inc.":
                    zscaler_non_malicious.append({
                        "ip": ip,
                        "status": f"{ip} is NON MALICIOUS due to its reliable ISP: Zscaler, Inc."
                    })
                    non_malicious.append(ip)
                elif confidence == 0 and reports == 0:
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

        if zscaler_non_malicious:
            zscaler_ips_only = [item["ip"] for item in zscaler_non_malicious]
            ticket_resolution += "ZSCALER NON-MALICIOUS: " + ",".join(zscaler_ips_only) + "\n"

        regular_non_malicious = [ip for ip in non_malicious if ip not in [item["ip"] for item in zscaler_non_malicious]]

        if regular_non_malicious:
            ticket_resolution += "NON-MALICIOUS: " + ",".join(regular_non_malicious) + "\n"
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

        ip_links = "\n".join([f"https://www.abuseipdb.com/check/{ip}" for ip in ip_list])
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
                f"CF Detection:\nIP Reputation: \n{ip_links}",
                "Spike detected, all requests blocked by WAF. No pending actions.",
                today + " - No pending actions. Ticket closure.",
                "Spike detected, all requests blocked by WAF. No pending actions."
            ]
        }

        df_resolution = pd.DataFrame(sheets_data)
        df_resolution.rename(columns={"Column A": "Column_A", "Column B": "Column_B"}, inplace=True)

        df_xss_resolutions = []

        for ip in ip_list:
            ip_result = next((r for r in results if r["IP_Address"] == ip), None)
            confidence = ip_result["Confidence_Score"] if ip_result else 0
            reports = ip_result["Reports"] if ip_result else 0

            ip_link = f"https://www.abuseipdb.com/check/{ip}"
            df_xss = self.build_xss_resolution(
                ip=ip,
                ip_links=ip_link,
                ojt_name=ojt_name,
                related_website=related_website,
                ticket_no=ticket_no,
                confidence=confidence,
                reports=reports,
                isp=isp
            )
            df_xss_resolutions.append(df_xss.to_dict(orient="records"))


        context = {
            "ip_input": ip_input,
            "related_website": related_website,
            "ticket_no": ticket_no,
            "ojt_name": ojt_name,
            "output": pd.DataFrame(results).to_dict(orient="records"),
            "ticket_resolution": ticket_resolution.strip(),
            "incident_log": incident_logs,
            "df_resolution": df_resolution.to_dict(orient="records"),
            "df_xss_resolutions": df_xss_resolutions, 
            "zscaler_ips": zscaler_non_malicious
        }

        return render(request, self.template_name, context)

    
