CT-subdomain Hunter is a passive reconnaissance tool that discovers and fingerprints subdomains using Certificate Transparency (CT) logs, DNS resolution, HTTP metadata extraction, and heuristic risk scoring.
Includes both a CLI scanner and a Streamlit web interface for easy visualization and reporting.

Steps to execute:
In root directory- ct-subdomain-hunter/ perform the following-
1.	python -m venv venv
2.	source venv/Scripts/activate   (Windows)
3.	pip install -r requirements.txt
4.	python main.py <target_domain>.com
And then, to use streamlit GUI-
1.	streamlit run ui/streamlit_app.py
