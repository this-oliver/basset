import os
import logging
import argparse
import re
from typing import List, Union

logger = logging.getLogger(__name__)

DEFAULT_METHODS = "GET"
DEFAULT_STATUS = "200,301"
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "TRACE"]

def get_logs(path: str) -> List[str]:
    if not os.path.exists(path):
       raise ValueError(f"File {path} does not exist")
    
    with open(path, 'r') as content:
      return [line.split("\n")[0] for line in content.readlines()]

def get_log_ip(log: str) -> Union[str, None]:
   pattern = r'^([0-9]{1,3}[.]){3}[0-9]{1,3}'
   matches = re.search(pattern, log)

   if matches is None:
    return None
   
   return matches[0]

def get_log_method(log: str) -> Union[str, None]:
  pattern = f'({"|".join(HTTP_METHODS)}) \\/'
  matches = re.findall(pattern, log)

  if matches is None or len(matches) == 0:
    return None
  
  return matches[0].split()[0]

def get_log_path(log: str) -> Union[str, None]:
  """
  TODO: find a better (not hard-coded) solution.

  This function tries to extract the path `/ HTTP/1.1` from the log `<IP Address> - - [DD/MMM/YYY:00:00:00 +0000] "GET / HTTP/1.1" 200 60880 "-" "Browser <DEVICE>"`
  by splitting the log by spaces so that it lookes like `['<IP Address>', '-', '-', '[DD/MMM/YYY:00:00:00', '+0000]', '"GET', '/', 'HTTP/1.1"', '200', '60880', '"-"', '"Browser', '<DEVICE>"']`
  and then removing all items up to the `/` that indicates the beggining of the path. These items are usually found at the 6th index in the list (HARD_CODED).

  After removing the first 6 items, the function rejoins the remaining items so that they look like `/ HTTP/1.1" 200 60880 "-" "Browser <DEVICE>"` and then it
  splits this new string by `"` to get everything up to the quotation mark before the status code.
  """
  result = None

  # splits log by spaces
  items = log.split(" ")
  
  # removes the first 6 items (see the functon docs for an explanation on the hard coded '6')
  if items and len(items) >= 6:
    items = items[6:]

  # rejojin the items and then immedietly split by `"` and extract the first item (see function docs for more info)
  items = " ".join(items).split("\"")
  if items and len(items) >= 1:
    result = items[0]

  return result

def find_logs_with_approved_methods(logs: List[str], approved_methods: List[str], inverse: bool = False) -> List[str]:
  matching_logs = []
  for log in logs:
    current_method = get_log_method(log)
    if inverse and current_method not in approved_methods:
      matching_logs.append(log)
    elif inverse is False and current_method in approved_methods:
      matching_logs.append(log)
  return matching_logs
   
def report(title: str, description: str, logs: List[str], max_logs: int = 10, verbose: bool = False) -> str:
  count = len(logs)

  if verbose is not True:
    processed_logs = []
    for log in logs:
        ip = get_log_ip(log)
        method = get_log_method(log)
        processed_logs.append(f"{ip} - {method}")
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