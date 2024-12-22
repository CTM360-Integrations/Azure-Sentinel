import logging
import hashlib
import hmac
import os
import azure.functions as func
import json
import re
import base64
import requests
import datetime
import traceback
import time  # <-- Use the time module (instead of from time import...)
from .state_manager import StateManager

# Environment Variables
cbs_api_key = os.environ.get('api_key')
customer_id = os.environ.get('WorkspaceID')
shared_key = os.environ.get('WorkspaceKey')
logAnalyticsUri = os.environ.get('logAnalyticsUri')
olddate_from = os.environ.get('date_from')
olddate_to = os.environ.get('date_to')
backupflag = os.environ.get('backupflag')
log_type = 'CBSLog_Azure_1_CL'
MAX_RETRIES = 3
RETRY_INTERVAL_SECONDS = 60
connection_string = os.environ['AzureWebJobsStorage']

# Ensure logAnalyticsUri has a default if empty
if not logAnalyticsUri or str(logAnalyticsUri).isspace():
    logAnalyticsUri = f'https://{customer_id}.ods.opinsights.azure.com'

pattern = r'https:\/\/([\w\-]+)\.ods\.opinsights\.azure.([a-zA-Z\.]+)$'
match = re.match(pattern, str(logAnalyticsUri))
if not match:
    raise Exception("CBS Data Connector: Invalid Log Analytics Uri.")

# Timezone offset if needed (e.g., UTC+3 => 3*3600). Currently set to 0.
bahrain_timezone_offset = 0

def format_iso8601(timestamp):
    """
    Convert a UNIX timestamp to 'DD-MM-YYYY HH:MM' in UTC.
    Example: 25-10-2024 13:55
    """
    return time.strftime("%d-%m-%Y %H:%M", time.gmtime(timestamp))

def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    """
    Build the authorization signature for Azure Log Analytics.
    """
    x_headers = 'x-ms-date:' + date
    string_to_hash = f"{method}\n{content_length}\n{content_type}\n{x_headers}\n{resource}"
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(
        hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()
    ).decode()
    authorization = f"SharedKey {customer_id}:{encoded_hash}"
    return authorization

def parse_response_data(response_json):
    """
    Different endpoints have different keys for the list of records:
      - Incidents => "incident_list"
      - Others (malware_logs, breached_credentials, card_leaks, domain_protection) => "hits"
    """
    if "incident_list" in response_json:
        return response_json["incident_list"]
    elif "hits" in response_json:
        return response_json["hits"]
    else:
        # If no known key, return the entire JSON (wrapped in a list).
        return [response_json]

def perform_request(url, headers):
    """
    Execute an HTTP GET request (with retries) and post the parsed results to Sentinel.
    """
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.get(url, headers=headers, timeout=(5, 10))
            response.raise_for_status()  # Raises HTTPError if status != 2xx/3xx

            if response.status_code == 429:
                # Too many requests => wait, then retry
                logging.warning("HTTP status code 429 (Too Many Requests). Retrying...")
                time.sleep(RETRY_INTERVAL_SECONDS)
            else:
                # Parse the JSON response and extract records
                message_json = response.json()
                records = parse_response_data(message_json)

                # Send the records to Sentinel
                post_data_to_sentinel(json.dumps(records))
                return True

        except requests.exceptions.RequestException as e:
            logging.warning(f"Request failed: {str(e)}")
            if attempt < MAX_RETRIES - 1:
                logging.info(f"Retrying in {RETRY_INTERVAL_SECONDS} seconds...")
                time.sleep(RETRY_INTERVAL_SECONDS)  # <-- Now works (using time.sleep)
            else:
                logging.error("Max retries reached. Exiting.")
                return False

def post_data_to_sentinel(body):
    """
    Send the final JSON payload to Azure Sentinel (Log Analytics Workspace).
    """
    method = 'POST'
    content_type = 'application/json'
    resource = '/api/logs'
    rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)

    signature = build_signature(
        customer_id, shared_key, rfc1123date, content_length, method, content_type, resource
    )

    uri = f"{logAnalyticsUri}{resource}?api-version=2016-04-01"
    headers = {
        'content-type': content_type,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date
    }

    try:
        response = requests.post(uri, data=body, headers=headers)
        if 200 <= response.status_code <= 299:
            logging.info("Data successfully sent to Azure Sentinel.")
            return response.status_code
        else:
            logging.error(f"Failed to send data. Response code: {response.status_code}")
            return None
    except Exception:
        logging.error("Exception occurred while posting data to Sentinel:")
        logging.error(traceback.format_exc())
        return None

def main(mytimer: func.TimerRequest) -> None:
    """
    Timer-triggered function entry point.
    Retrieves data from multiple cbs.ctm360.com endpoints,
    appends date_from/date_to, and posts the logs to Azure Sentinel.
    """
    if mytimer.past_due:
        logging.warning('The timer is past due!')

    # Current UTC timestamp (in seconds)
    current_time = time.time()
    # Subtract 5 minutes from the current time, plus any offset
    five_minutes_ago_bahrain = current_time - 5 * 60 + bahrain_timezone_offset

    current_time_str = format_iso8601(current_time + bahrain_timezone_offset)
    five_minutes_ago_str = format_iso8601(five_minutes_ago_bahrain)

    # Endpoints we want to query
    endpoints = [
        "https://cbs.ctm360.com/api/v2/incidents",
        "https://cbs.ctm360.com/api/v2/leaks/malware_logs",
        "https://cbs.ctm360.com/api/v2/leaks/breached_credentials",
        "https://cbs.ctm360.com/api/v2/leaks/card_leaks",
        # Domain Protection (two types)
        "https://cbs.ctm360.com/api/v2/domain_protection?size=5000&risk_score_min=60&risk_score_max=100&type=subdomain_infringement",
        "https://cbs.ctm360.com/api/v2/domain_protection?size=5000&risk_score_min=60&risk_score_max=100&type=domain_infringement"
    ]

    headers = {
        "accept": "application/json",
        "api-key": cbs_api_key
    }

    # Determine whether to use backup mode or incremental
    if backupflag == "true":
        state = StateManager(connection_string)
        backup_status = state.get()
        if backup_status in [None, "", "false"]:
            date_from, date_to = olddate_from, olddate_to
            # Mark that the backup ingestion has been done
            state.post("true")
        else:
            # Use the last 5 minutes
            date_from, date_to = five_minutes_ago_str, current_time_str
    else:
        # Normal incremental mode (last 5 minutes)
        date_from, date_to = five_minutes_ago_str, current_time_str

    # Fetch data from each endpoint, appending date_from/date_to
    for endpoint in endpoints:
        if "?" in endpoint:
            url = f"{endpoint}&date_from={date_from}&date_to={date_to}"
        else:
            url = f"{endpoint}?date_from={date_from}&date_to={date_to}"

        logging.warning(f"Request URL => {url}")

        success = perform_request(url, headers)
        if success:
            logging.info(f"Data successfully retrieved and posted from {endpoint}")
        else:
            logging.error(f"Failed to retrieve data from {endpoint}")
