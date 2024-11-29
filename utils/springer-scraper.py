import csv
import os
import requests
import shutil
from bs4 import BeautifulSoup
import json

# Define input CSV file and output RIS file
CSV_FILE = 'SearchResults.csv'
OUTPUT_RIS = 'SpringerLink.ris'
TEMP_DIR = 'temp_ris_files'

# Base URL templates
citation_url_template = "https://citation-needed.springer.com/v2/references/PLACEHOLDER?format=refman&flavour=citation"
article_url_template = "https://link.springer.com/article/PLACEHOLDER"

# Create a temporary directory for storing downloaded .RIS files
os.makedirs(TEMP_DIR, exist_ok=True)

# Open the output RIS file
with open(OUTPUT_RIS, 'w') as output_file:
    # Start a session to handle cookies and redirects
    session = requests.Session()

    # Read the CSV file
    with open(CSV_FILE, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        
        for row in reader:
            item_doi = row["Item DOI"].strip('"')  # Remove quotes if present
            
            # Create the download URL for the .RIS file
            download_url = citation_url_template.replace("PLACEHOLDER", item_doi)
            
            # Define a safe filename for storing the .RIS file
            safe_filename = item_doi.replace("/", "_") + ".ris"
            ris_filepath = os.path.join(TEMP_DIR, safe_filename)

            # Access the article page URL
            article_url = article_url_template.replace("PLACEHOLDER", item_doi)

            try:
                # Step 1: Download the .RIS file
                response = session.get(download_url, allow_redirects=True)
                ris_content = ""
                if response.status_code == 200:
                    ris_content = response.text

                else:
                    print(f"Failed to download .RIS file for DOI: {item_doi}, Status Code: {response.status_code}")

                # Step 2: Access the article page and extract keywords
                article_response = session.get(article_url, allow_redirects=True)
                keywords = []
                if article_response.status_code == 200:
                    # Parse the HTML content
                    soup = BeautifulSoup(article_response.text, 'html.parser')
                    
                    # Find the JSON object in the <script> tag
                    script_tag = soup.find('script', type="application/ld+json")
                    if script_tag:
                        try:
                            json_data = json.loads(script_tag.string)
                            main_entity = json_data.get("mainEntity", {})
                            keywords = main_entity.get("keywords", [])
                        except json.JSONDecodeError as e:
                            print(f"Error parsing JSON for DOI {item_doi}: {e}")
                    else:
                        print(f"No <script type='application/ld+json'> tag found for DOI: {item_doi}")

                else:
                    print(f"Failed to access article page for DOI: {item_doi}, Status Code: {article_response.status_code}")

                # Step 3: Add keywords to the RIS entry
                if ris_content:
                    ris_lines = ris_content.splitlines()
                    # Add the keywords in the RIS format
                    for keyword in keywords:
                        ris_lines.insert(-1, f"KW  - {keyword}")  # Insert before the 'ER  - ' line
                    
                    # Join the RIS content back together
                    enriched_ris_content = "\n".join(ris_lines)

                    # Write the enriched RIS content to the output file
                    output_file.write(enriched_ris_content + "\n\n")
                
            except requests.RequestException as e:
                print(f"Error processing DOI: {item_doi}, Error: {e}")

# Clean up the temporary directory
shutil.rmtree(TEMP_DIR)
print(f"Final .RIS file created: {OUTPUT_RIS}")
