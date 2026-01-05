import os
import logging
import argparse
import re
from typing import List, Union

logger = logging.getLogger(__name__)

DEFAULT_METHODS = "GET"
DEFAULT_STATUS = "200,301"
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "TRACE"]

def get_formatted_number(num: str) -> int:
  return "{:,}".format(num)

def get_logs(path: str) -> List[str]:
  if not os.path.exists(path):
    raise ValueError(f"File {path} does not exist")
  
  with open(path, 'r') as content:
    return [line.split("\n")[0] for line in content.readlines()]
class LogExtractor:
  def get_ip(self, log_line: str) -> Union[str, None]:
    """Extracts the IP address from an Nginx log line."""
    match = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', log_line)
    return match.group(1) if match else None

  def get_time(self, log_line: str) -> Union[str, None]:
    """Extract the date from the Nginx log line"""
    pattern = r'\[(.*?)\]'
    matches = re.findall(pattern, log_line)

    if matches is None or len(matches) == 0:
      return None
    
    return matches[0]

  def get_method(self, log_line: str) -> Union[str, None]:
    """Extracts HTTP method from an Nginx log line"""
    pattern = f'({"|".join(HTTP_METHODS)}) \\/'
    matches = re.findall(pattern, log_line)

    if matches is None or len(matches) == 0:
      return None
    
    return matches[0].split()[0]

  def get_path(self, log_line: str) -> Union[str, None]:
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

  def get_status_code(self, log_line: str) -> Union[str, None]:
    """Extracts the HTTP status code from an Nginx log line."""
    match = re.search(r'(?<=(HTTP\/1.0|HTTP\/1.1|HTTP\/2.0)" )[0-9]+', log_line) # Match 3 digit code after HTTP protocol

    if match is None:
      match = re.search(r'(?<=" )[0-9]+', log_line) # Match 3 digit code after HTTP protocol quotation

    return match[0] if match else None

  def get_size(self, log_line: str) -> Union[str, None]:
    """Extracts the response size in bytes from an Nginx log"""
    match = re.search(r'/(?<=(HTTP\/1.0|HTTP\/1.1|HTTP\/2.0)" )[0-9]+ [0-9]+', log_line) # Match multi two sets of digits after HTTP protocol

    if match is None:
      match = re.search(r'(?<=" )[0-9]+ [0-9]+', log_line) # Match multi two sets of digits after HTTP protocol quotation

    return match[0].split(" ")[1] if match else None

  def get_agent(self, log_line: str) -> Union[str, None]:
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

  def to_object(self, log_line: str) -> dict:
    """Returns a dictionary containing the log data."""
    
    return {
      "ip": self.get_ip(log_line),
      "time": self.get_time(log_line),
      "method": self.get_method(log_line),
      "path": self.get_path(log_line),
      "status_code": self.get_status_code(log_line),
      "response_size": self.get_size(log_line),
      "user_agent": self.get_agent(log_line)
      }

class LogAnalyzer:
  extractor = LogExtractor()

  def __init__(self, logs: List[str], verbose: bool):
    self.logs = logs
    self.verbose = verbose

  def find_logs_with_approved_methods(self, approved_methods: List[str], inverse: bool = False) -> List[str]:
    matching_logs = []
    for log in self.logs:
      current_method = self.extractor.get_method(log)
      if inverse and current_method not in approved_methods:
        matching_logs.append(log)
      elif inverse is False and current_method in approved_methods:
        matching_logs.append(log)
    return matching_logs
    
  def find_logs_with_approved_status(self, approved_status_codes: List[int], inverse: bool = False) -> List[str]:
    matching_logs = []
    for log in self.logs:
      current_status = self.extractor.get_status_code(log)
      if inverse and current_status not in approved_status_codes:
        matching_logs.append(log)
      elif inverse is False and current_status in approved_status_codes:
        matching_logs.append(log)
    return matching_logs

def report(title: str, description: str, logs: List[str], max_logs: int = 10, verbose: bool = False) -> str:
  extractor = LogExtractor()
  count = len(logs)

  if verbose is not True:
    processed_logs = []
    for log in logs:
        ip = extractor.get_ip(log)
        method = extractor.get_method(log)
        path = extractor.get_path(log)
        processed_logs.append(f"{ip} - {method} - {path}")
    logs = processed_logs
  
  if len(logs) > max_logs:
    logs = logs[:max_logs]
    logs.append(f"... ({get_formatted_number(count - max_logs)} more)")

  if len(logs) > 0:
    logs = "\n".join(logs)
    logs = f"Logs:\n{logs}"
  else:
    logs = "No logs found"

  return f"Title: {title}\nDescription: {description}\n\n{logs}"

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
      analyzer = LogAnalyzer(logs=get_logs(args.file), verbose=verbose)
      reports = []

      sus_methods = analyzer.find_logs_with_approved_methods(approved_methods=methods, inverse=True)
      reports.append(report(
          title="Suspicious Methods",
          description=f"Logs with HTTP methods that are not {','.join(methods)}",
          logs=sus_methods,
          verbose=verbose
      ))

      sus_status = analyzer.find_logs_with_approved_status(approved_status_codes=status_codes, inverse=True)
      reports.append(report(
          title="Suspicious Status",
          description=f"Logs with HTTP status codes that are not {','.join(status_codes)}",
          logs=sus_methods,
          verbose=verbose
      ))

      for report in reports:
          print("\n==================")
          print(report)
      
      print(f"\n\nTotal logs: {get_formatted_number(len(analyzer.logs))}")
    except ValueError as e:
        logger.error(f"error: {e}")
        parser.print_help()
        parser.exit(status=1)