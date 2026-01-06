import re
from typing import Union
from src.common.constants import SAFE_HTTP_METHODS as HTTP_METHODS

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
    whole_path = re.search(r'(?<=] ").+(?=" \d)', log_line) # Match everything between the quotes after the date's `]` and the first digit in the status code
    
    if whole_path is None:
      return None
    
    whole_path = whole_path.group(0)

    # remove method if it exists
    if whole_path.upper().startswith(tuple(HTTP_METHODS)):
      items = whole_path.split(" ")[1:]
      whole_path = " ".join(items)

    # remove the protocol if it exists
    protocol = re.search(r'HTTP\/\d+\.\d+', whole_path)
    if protocol is not None:
      items = whole_path.split(" ")
      items.pop()
      whole_path = " ".join(items)

    return whole_path.strip()

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

