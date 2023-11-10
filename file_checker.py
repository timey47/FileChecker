import requests

def check_url(api_key, url):
    # VirusTotal API endpoint for URL scan
    api_url = 'https://www.virustotal.com/vtapi/v2/url/report'

    # Parameters for the API request
    params = {'apikey': api_key, 'resource': url}

    try:
        # Make the API request
        response = requests.get(api_url, params=params)
        result = response.json()

        # Check the response code
        if response.status_code == 200:
            # Check if the URL is malicious or not
            if result['response_code'] == 1:
                print(f"The URL '{url}' is rated as {result['positives']} malicious out of {result['total']} scanners.")
                
                # Print detailed information about individual scan engines
                print("Individual Scan Engine Results:")
                for scan_engine, result in result['scans'].items():
                    print(f"{scan_engine}: {result['result']}")

            else:
                print(f"The URL '{url}' is not detected as malicious by any scanners.")
        else:
            print(f"Error: {result['verbose_msg']}")

    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    # Read the API key from the environment variable
    api_key = os.environ.get('VIRUSTOTAL_API_KEY')
    if not api_key:
        print("Error: Please set the VIRUSTOTAL_API_KEY environment variable.")
        exit(1)

    url_to_check = input("Enter the URL to check: ")
    check_url(api_key, url_to_check)
