# OTX to MISP Synchronization Script

This script fetches events from AlienVault OTX (Open Threat Exchange) and adds them to MISP (Malware Information Sharing Platform & Threat Sharing).

## Requirements

Make sure you have the following prerequisites installed:

- Python 3.x
- Required Python packages (install using `pip install -r requirements.txt`):
  - OTXv2
  - pymisp
  - python-dotenv
  - urllib3: Just to ignore some SSL errors, can be removed.

## Configuration

1. Create a `.env` file in the script directory.
2. Add the following configuration variables with your actual values:

   ```env
   OTX_API_KEY=<Your_OTX_API_Key>
   MISP_API_KEY=<Your_MISP_API_Key>
   MISP_URL=<Your_MISP_URL>
   ```

## Usage

Run the script using the following command:

```bash
python otx_collector.py
```

Replace `otx_collector.py` with the actual name of your script.

## Script Overview

- **otx_api_key**: API key for AlienVault OTX. [https://otx.alienvault.com/settings](https://otx.alienvault.com/settings)
- **misp_api_key**: API key for MISP. https://your_misp/auth_keys/index
- **misp_url**: URL of your MISP instance.
- **misp_verify_cert**: Set to `True` if MISP server uses SSL/TLS.

### Functions

1. **fetch_and_add_to_misp()**: Fetches OTX events and adds them to MISP.

2. **misp_event_exists(misp, pulse)**: Checks if a MISP event already exists based on the Pulse ID.

3. **create_misp_event(pulse)**: Creates a MISP event from an OTX pulse.

4. **add_otx_iocs_to_misp(misp, pulse, misp_event)**: Adds OTX IOCs to a MISP event.

## Customization

- Modify the threat level (`threat_level_id`), analysis (`analysis`), and other event attributes in the `create_misp_event` function as needed.

- Adjust the MISP attribute type, value, and other parameters in the `add_otx_iocs_to_misp` function based on your requirements.

## Issues and Contributions

Feel free to open issues or contribute to the development of this script. Pull requests are welcome!
