import os
import json
from flask import Flask, request, jsonify, send_file
from bs4 import BeautifulSoup

app = Flask(__name__)

# Reports directory
REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

# Example hash to display on homepage
EXAMPLE_HASH = "296e623e1ab7aea092d5bc9eeec7f841"


def load_json_file(filename):
    """Load JSON from file if it exists."""
    path = os.path.join(REPORTS_DIR, filename)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# --- Root endpoint with instructions ---
@app.route("/", methods=["GET"])
def home():
    instructions = f"""
    <h2>📌 MobSF Report API</h2>
    <p>This API serves pre-generated reports stored in the <code>/reports</code> folder.</p>
    
    <h3>Example Hash:</h3>
    <p><b>{EXAMPLE_HASH}</b></p>

    <h3>Available Endpoints:</h3>
    <ul>
        <li><b>Get a specific JSON report</b><br>
            <code>GET /report?file=scan_response.json</code>
        </li>
        
        <li><b>Get compiled reports (aggregated)</b><br>
            <code>GET /compiled_reports</code>
        </li>

        <li><b>Get Scorecard JSON</b><br>
            <code>GET /scorecard</code>
        </li>
        
        <li><b>Get Malware Scrape (parsed HTML report)</b><br>
            <code>GET /malware_scrape?hash={EXAMPLE_HASH}</code>
        </li>

        <li><b>Download PDF report by hash</b><br>
            <code>GET /report_pdf?hash={EXAMPLE_HASH}</code>
        </li>
    </ul>

    <h3>Sample URLs:</h3>
    <ul>
        <li><a href="/report?file=scan_response.json">/report?file=scan_response.json</a></li>
        <li><a href="/compiled_reports">/compiled_reports</a></li>
        <li><a href="/scorecard">/scorecard</a></li>
        <li><a href="/malware_scrape?hash={EXAMPLE_HASH}">/malware_scrape?hash={EXAMPLE_HASH}</a></li>
        <li><a href="/report_pdf?hash={EXAMPLE_HASH}">/report_pdf?hash={EXAMPLE_HASH}</a></li>
    </ul>
    """
    return instructions


# --- API Endpoints ---

@app.route("/report", methods=["GET"])
def get_report():
    filename = request.args.get("file")
    if not filename:
        return jsonify({"error": "file query parameter is required"}), 400
    
    data = load_json_file(filename)
    if not data:
        return jsonify({"error": f"Report '{filename}' not found"}), 404
    
    return jsonify(data)


@app.route("/compiled_reports", methods=["GET"])
def compiled_reports():
    filenames = ["scan_response.json", "scan_logs.json", "scorecard.json"]
    aggregated = {}
    
    for fn in filenames:
        data = load_json_file(fn)
        if data:
            aggregated[fn] = data
    
    if not aggregated:
        return jsonify({"error": "No reports found"}), 404
    
    return jsonify(aggregated)


@app.route("/scorecard", methods=["GET"])
def scorecard():
    """Return scorecard.json if available"""
    data = load_json_file("scorecard.json")
    if not data:
        return jsonify({"error": "scorecard.json not found"}), 404
    return jsonify(data)


@app.route("/malware_scrape", methods=["GET"])
def malware_scrape():
    """
    Parse a stored static analyzer HTML report and return JSON.
    Example: /malware_scrape?hash=296e623e1ab7aea092d5bc9eeec7f841
    """
    apk_hash = request.args.get("hash")
    if not apk_hash:
        return jsonify({"error": "hash query parameter is required"}), 400

    html_file = os.path.join(REPORTS_DIR, f"{apk_hash}_static_analyzer.html")
    if not os.path.exists(html_file):
        return jsonify({"error": "Static analyzer HTML report not found"}), 404

    with open(html_file, "r", encoding="utf-8") as f:
        soup = BeautifulSoup(f, "html.parser")

    result = {
        "malware_lookup": {},
        "apkid_analysis": [],
        "behaviour_analysis": [],
        "domain_malware_check": [],
        "urls": [],
        "emails": []
    }

    def extract_table(section_id):
        anchor = soup.find("a", {"id": section_id})
        if not anchor:
            return []
        table = anchor.find_next("table")
        if not table:
            return []
        headers = [h.get_text(strip=True).lower() for h in table.find_all("th")]
        rows = []
        for tr in table.find_all("tr")[1:]:
            cols = [td.get_text(" ", strip=True) for td in tr.find_all("td")]
            if cols:
                rows.append(dict(zip(headers, cols)))
        return rows

    # Malware lookup links
    malware_section = soup.find("a", {"id": "malware_lookup"})
    if malware_section:
        container = malware_section.find_next("section")
        if container:
            links = container.find_all("a", href=True)
            for link in links:
                text = link.get_text(strip=True).lower()
                href = link["href"]
                if "virustotal" in text:
                    result["malware_lookup"]["virustotal"] = href
                elif "triage" in text:
                    result["malware_lookup"]["triage"] = href
                elif "metadefender" in text:
                    result["malware_lookup"]["metadefender"] = href
                elif "hybrid" in text:
                    result["malware_lookup"]["hybrid_analysis"] = href

    result["apkid_analysis"] = extract_table("apkid")
    result["behaviour_analysis"] = extract_table("behaviour")
    result["domain_malware_check"] = extract_table("malware_check")
    result["urls"] = extract_table("urls")
    result["emails"] = extract_table("emails")

    return jsonify({"hash": apk_hash, "parsed_report": result})


@app.route("/report_pdf", methods=["GET"])
def report_pdf():
    apk_hash = request.args.get("hash")
    if not apk_hash:
        return jsonify({"error": "hash query parameter is required"}), 400
    
    pdf_path = os.path.join(REPORTS_DIR, f"{apk_hash}_report.pdf")
    if not os.path.exists(pdf_path):
        return jsonify({"error": "PDF not found"}), 404
    
    return send_file(pdf_path, mimetype="application/pdf")


if __name__ == "__main__":
    app.run(debug=True, port=5000)
