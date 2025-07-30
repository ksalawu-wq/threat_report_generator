🛡️ AI Threat Report Generator



The **AI Threat Report Generator** is a Streamlit-powered web application that analyzes uploaded `.txt`, `.log`, or `.pcap` files to generate a detailed, structured cybersecurity threat report. This tool is ideal for security analysts, SOC teams, students, and incident responders who want a fast, AI-assisted way to extract IOCs, understand event timelines, and identify remediation steps.



📌 Features



\- ✅ Upload and analyze `.txt`, `.log`, and `.pcap` files

\- 🔍 Extract \*\*Indicators of Compromise (IOCs)\*\* (IPs, ports)

\- 📅 Generate a \*\*Timeline of Events\*\*

\- 🛡️ Provide \*\*Remediation Recommendations\*\*

\- 💡 Summarize threats in an \*\*Executive Summary\*\*

\- 📡 Detect and summarize \*\*C2 Communication Patterns\*\*

\- 🖥️ Identify \*\*Initial Compromise Point\*\* and attack vectors

\- 🧠 AI/NLP-ready structure for future LLM integration



📂 Folder Structure





threat\\\_report\\\_generator/

│

├── app.py                    # Main Streamlit app

├── utils.py                  # File parsing and report logic

├── uploads/                  # Temporary storage for uploaded files

└── README.md                 # Project documentation





🚀 Installation \& Setup



Prerequisites

\- Python 3.8+

\- pip (Python package manager)



Installation Steps



```bash

\# 1. Clone the repository

git clone https://github.com/your-username/threat\_report\_generator.git

cd threat\_report\_generator



\# 2. Create virtual environment (recommended)

python -m venv venv

source venv/bin/activate   # On Windows: venv\\Scripts\\activate



\# 3. Install dependencies

pip install -r requirements.txt

````



> Example `requirements.txt`:



```

streamlit

scapy

```



🧠 Usage



```bash

streamlit run app.py

```



Once launched:



1\. Open browser to the local Streamlit address (usually \[http://localhost:8501](http://localhost:8501)).

2\. Upload a `.txt`, `.log`, or `.pcap` file.

3\. Click \*\*"🧠 Generate Threat Report"\*\* to analyze and view results.



---



📝 Example



Uploaded `.pcap` or `.log` Output:



\* **Executive Summary**:

&nbsp; "The uploaded PCAP file contains 320 events, with 12 unique IPs interacting over TCP. C2 beaconing patterns were detected. The initial compromise seems to originate from internal IP 192.168.1.25."



\* **IOCs**:



&nbsp; ```

&nbsp; 192.168.1.25:443

&nbsp; 203.0.113.99:80

&nbsp; 198.51.100.34:4444

&nbsp; ```



\* **Timeline of Events**:



&nbsp; ```

&nbsp; 2025-07-29 14:20:03 - TCP from 192.168.1.25:55632 to 198.51.100.34:4444

&nbsp; 2025-07-29 14:20:08 - TCP from 192.168.1.25:55632 to 198.51.100.34:4444

&nbsp; ```



\* **C2 Communication Pattern**:



&nbsp; ```

&nbsp; Persistent TCP beaconing every 5 seconds from internal host 192.168.1.25 to external IP 198.51.100.34:4444.

&nbsp; ```



\* **Initial Compromise**:



&nbsp; ```

&nbsp; Initial activity detected at 14:20:03 from internal host 192.168.1.25 to unknown public IP on uncommon port 4444.

&nbsp; Likely attack vector: malicious file download or phishing payload.

&nbsp; ```



\* **Remediation Steps**:



&nbsp; \* Block malicious IPs at perimeter firewalls.

&nbsp; \* Investigate host 192.168.1.25 for compromise.

&nbsp; \* Update antivirus and perform full scans.

&nbsp; \* Review proxy and DNS logs for further exfiltration attempts.



🛡️ Security Considerations



\* All uploaded files are saved temporarily in a local `/uploads` folder.

\* Only `.txt`, `.log`, and `.pcap` files are accepted.

\* Basic filename sanitization is in place.

\* PCAP files are parsed safely using Scapy with error handling.

\* **Future Recommendation**:



&nbsp; \* Use Docker sandboxing for file parsing.

&nbsp; \* Enable access control for production deployments.

&nbsp; \* Sanitize sensitive information before display.



🧱 Future Work



\* Integration with GPT-based NLP for natural language threat description

\* IOC enrichment using external threat intel sources (e.g., VirusTotal API)

\* Exportable PDF/HTML reports

\* Web deployment (e.g., Streamlit Cloud, Heroku, Docker)



📧 Contact



Created by **Kabiru Muhammad Salawu**

For inquiries, reach out at: `sakabiru11@gmail.com`

GitHub: https://github.com/ksalawu-wq



📝 License



This project is open-source under the MIT License.





