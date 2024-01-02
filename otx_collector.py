from OTXv2 import OTXv2
from pymisp import PyMISP, MISPEvent
from datetime import datetime, timedelta
from dotenv import load_dotenv
import urllib3, logging, os 

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load variables from the .env file
load_dotenv()

# Replace these placeholders with your actual values in .env
otx_api_key = os.getenv('OTX_API_KEY')
misp_api_key = os.getenv('MISP_API_KEY')
misp_url = os.getenv('MISP_URL')
misp_verify_cert = False # Set to True if MISP server uses SSL/TLS

# Function to fetch OTX events and add them to MISP in .env
def fetch_and_add_to_misp():
    try:
        otx = OTXv2(otx_api_key)
        misp = PyMISP(misp_url, misp_api_key, misp_verify_cert)

        # Calculate the date 30 days ago from the current date
        thirty_days_ago = datetime.now() - timedelta(days=5)

        # Get OTX pulses modified in the last 30 days
        pulses = otx.getall(modified_since=thirty_days_ago)

        for pulse in pulses:
            if len(pulse['indicators']) != 0:
            # Check if the pulse already exists in MISP
                if not misp_event_exists(misp, pulse):
                    # Tags to add
                    tags = pulse['tags'] + \
                           pulse['targeted_countries'] + \
                           pulse['malware_families'] + \
                          ['AlienVault',pulse['id']]
                    tags.append(f"TLP:{pulse['tlp']}")
          
                    # Create a MISP event
                    misp_event = create_misp_event(pulse)

                    # Add MISP attributes from the OTX pulse
                    add_otx_iocs_to_misp(misp, pulse, misp_event)
                    for tag in tags:
                        misp_event.add_tag(tag)

                    try:
                        # Add the event to MISP
                        misp.add_event(misp_event, pythonify=True)
                        logging.info(f"Event '{misp_event.info}' added to MISP successfully.")
                    except Exception as add_event_error:
                        logging.error(f"Error adding event '{misp_event.info}' to MISP: {str(add_event_error)}")
                else:
                    logging.info(f"Event '{pulse['name']}' with Pulse ID '{pulse['id']}' already exists in MISP. Skipping.")
            else:
                logging.info(f"Event '{pulse['name']}' with Pulse ID '{pulse['id']}' has no indicators. Skipping.")

    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")

# Function to check if a MISP event already exists
def misp_event_exists(misp, pulse):
    # Search based on the Pulse ID
    existing_events = misp.search(tag=pulse['id'])
    return bool(existing_events)

# Function to create a MISP event from OTX pulse
def create_misp_event(pulse):
    misp_event = MISPEvent()
    misp_event.info = pulse['name']
    misp_event.threat_level_id = 2  # Modify as needed
    misp_event.analysis = 2  # Modify as needed
    misp_event.published = True  # Modify as needed
    misp_event.distribution = 0

    return misp_event

# Function to add OTX IOCs to MISP event
def add_otx_iocs_to_misp(misp, pulse, misp_event):
    for indicator in pulse['indicators']:
        # Add MISP attribute based on the OTX indicator
        misp_attribute = {
            'type': 'text',  # Modify as needed
            'value': indicator['indicator'],
            'comment': indicator.get('description', ''),
            'to_ids': True  # Modify as needed
        }
        
        # Add the attribute to the MISP event
        misp_event.add_attribute(**misp_attribute)

# Main script
if __name__ == "__main__":
    fetch_and_add_to_misp()
