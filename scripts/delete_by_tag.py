from pymisp import PyMISP
from dotenv import load_dotenv
import urllib3, logging, os 

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load variables from the .env file
load_dotenv()

# Replace these placeholders with your actual values in .env
misp_api_key = os.getenv('MISP_API_KEY')
misp_url = os.getenv('MISP_URL')
misp_verify_cert = False

# Function to search for events based on a tag
def search_and_delete_events_by_tag(tag_name):
    try:
        misp = PyMISP(misp_url, misp_api_key, misp_verify_cert)

        # Search for events with the specified tag
        search_result = misp.search(tags=tag_name)

        
        for event in search_result:
            # Delete the event by ID
            misp.delete_event(event['Event']['id'])
            
            print(f"Event ID {event['Event']['id']} deleted successfully.")

    except Exception as e:
        print(f"An error occurred: {str(e)}")

# Main script
if __name__ == "__main__":
    # Replace 'AlienVault' with the tag you want to search for and delete events
    search_and_delete_events_by_tag('AlienVault')
