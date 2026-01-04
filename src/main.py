import os
import logging
import argparse
import re
from typing import List, Union

logger = logging.getLogger(__name__)

DEFAULT_METHODS = "GET"
DEFAULT_STATUS = "200,301"
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "TRACE"]

def extract_ip(log_line: str) -> Union[str, None]:
  """Extracts the IP address from an Nginx log line."""
  match = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', log_line)
  return match.group(1) if match else None

def extract_method(log_line: str) -> Union[str, None]:
  """Extracts HTTP method from an Nginx log line"""
  pattern = f'({"|".join(HTTP_METHODS)}) \\/'
  matches = re.findall(pattern, log_line)

  if matches is None or len(matches) == 0:
    return None
  
  return matches[0].split()[0]

def extract_path(log_line: str) -> Union[str, None]:
  """Extracts the request path/endpoint from an Nginx log line."""
  match = re.search(r'(?<=").+HTTP\/\d\.\d"', log_line) # Match anything in quotes after request

  if match is None:
    return None

  endpoint = match[0]
  items = endpoint.split(" ")
  items = items[1:]

  endpoint_without_method = " ".join(items)
  match = re.search(r'.+(?=HTTP\/\d\.\d")', endpoint_without_method)
  return match[0] if match is not None else None

def extract_status_code(log_line: str) -> Union[str, None]:
  """Extracts the HTTP status code from an Nginx log line."""
  match = re.search(r'(?<=(HTTP\/1.0|HTTP\/1.1|HTTP\/2.0)" )[0-9]+', log_line) # Match 3 digit code after HTTP protocol

  if match is None:
    match = re.search(r'(?<=" )[0-9]+', log_line) # Match 3 digit code after HTTP protocol quotation

  return match[0] if match else None

def extract_size(log_line: str) -> Union[str, None]:
  """Extracts the response size in bytes from an Nginx log"""
  match = re.search(r'/(?<=(HTTP\/1.0|HTTP\/1.1|HTTP\/2.0)" )[0-9]+ [0-9]+', log_line) # Match multi two sets of digits after HTTP protocol

  if match is None:
    match = re.search(r'(?<=" )[0-9]+ [0-9]+', log_line) # Match multi two sets of digits after HTTP protocol quotation

  return match[0].split(" ")[1] if match else None

def extract_agent(log_line: str) -> Union[str, None]:
  """Extracts the user agent string and attempts to identify the device from it."""
  match = re.search(r'(?<=" ").+(?="$)', log_line)
  user_agent = match[0] if match else None
  if user_agent:
    if "Android" in user_agent:
      return "Android"
    elif "iPhone" in user_agent or "iPad" in user_agent:
      return "iOS"
    elif "Windows" in user_agent:
      return "Windows"
    elif "Mac" in user_agent:
      return "Mac"
    elif "-" == user_agent:
      return "N/A"
    else:
      match = re.search(r'(?<=\()[a-zA-Z0-9\s\.:;\-\/_]+(?=\))', user_agent)
      return match[0] if match else "Unknown"
  return None

def get_logs(path: str) -> List[str]:
    if not os.path.exists(path):
       raise ValueError(f"File {path} does not exist")
    
    with open(path, 'r') as content:
      return [line.split("\n")[0] for line in content.readlines()]

def find_logs_with_approved_methods(logs: List[str], approved_methods: List[str], inverse: bool = False) -> List[str]:
  matching_logs = []
  for log in logs:
    current_method = extract_method(log)
    if inverse and current_method not in approved_methods:
      matching_logs.append(log)
    elif inverse is False and current_method in approved_methods:
      matching_logs.append(log)
  return matching_logs
  
def find_logs_with_approved_status(logs: List[str], approved_status_codes: List[int], inverse: bool = False) -> List[str]:
  matching_logs = []
  for log in logs:
    current_status = extract_status_code(log)
    if inverse and current_status not in approved_status_codes:
      matching_logs.append(log)
    elif inverse is False and current_status in approved_status_codes:
      matching_logs.append(log)
  return matching_logs
   
def report(title: str, description: str, logs: List[str], max_logs: int = 10, verbose: bool = False) -> str:
  count = len(logs)

  if verbose is not True:
    processed_logs = []
    for log in logs:
        ip = extract_ip(log)
        method = extract_method(log)
        path = extract_path(log)
        processed_logs.append(f"{ip} - {method} - {path}")
    logs = processed_logs
  
  if len(logs) > max_logs:
    logs = logs[:max_logs]
    logs.append(f"... ({count - max_logs} more)")

  if len(logs) > 0:
    logs = "\n".join(logs)
    logs = f"Logs:\n{logs}"
  else:
     logs = "No logs found"

  return f"==========\nTitle: {title}\nDescription: {description}\n\n{logs}\n=========="

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    parser = argparse.ArgumentParser(prog="Basset",description="Analyze your Nginx logs")
    parser.add_argument("file")
    parser.add_argument("-s", "--status", default=DEFAULT_STATUS, help="Specify normal HTTP status codes comma-separated")
    parser.add_argument("-m", "--methods", default=DEFAULT_METHODS, help="Specify normal HTTP methods comma-separated")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show extensive reports")
    parser.add_argument("-d", "--debug", action="store_true", help="Show debug logs")

    args = parser.parse_args()
    status_codes = args.status.split(",")
    methods = args.methods.split(",")
    verbose = args.verbose
    debug = args.debug

    if debug:
      logger.setLevel(logging.DEBUG)
      logger.debug(f"Config - Approved status: {status_codes}")
      logger.debug(f"Config - Approved methods: {methods}")
      logger.debug(f"Config - Verbose: {debug}")

    try:
      logs = get_logs(args.file)
          
      reports = []

      sus_methods = find_logs_with_approved_methods(logs=logs, approved_methods=methods, inverse=True)
      reports.append(report(
          title="Suspicious Methods",
          description=f"Logs with HTTP methods that are not {','.join(methods)}",
          logs=sus_methods,
          verbose=verbose
      ))

      for report in reports:
          print(report)
      
      print(f"Total logs: {len(logs)}")
    except ValueError as e:
        logger.error(f"error: {e}")
        parser.print_help()
        parser.exit(status=1)