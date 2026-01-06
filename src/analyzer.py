import re
from typing import List
from src.extractor import LogExtractor
from src.common.constants import SAFE_MEDIA_EXTENSIONS, UNSAFE_PHP_FILES

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

  def find_sus_paths(self) -> List[str]:
    matching_logs = []
    for log in self.logs:
      current_path = self.extractor.get_path(log)
      if current_path is None or current_path.strip() == "":
        matching_logs.append(log) # if you cant find a valid path, its sus
        continue
      sus_file = re.findall(r'(?<=\/)[\w|\d]*\.[\w|\d]*', current_path)
      if sus_file is None or len(sus_file) == 0:
        continue # sus file not found, skip to next log
      sus_file = str(sus_file[0].lower().strip())
      if sus_file.endswith(".html"):
        continue # this is most likely a normal HTML file
      elif sus_file.endswith(tuple(SAFE_MEDIA_EXTENSIONS)):
        continue # this is most likely a normal media file
      elif current_path.startswith(("/_nuxt/", "/api/_nuxt/", "/api/_nuxt_icon")) and sus_file.endswith((".js", ".json", ".css")):
        continue # this is most likely a bundled js file
      elif sus_file.endswith(".php") and sus_file not in UNSAFE_PHP_FILES:
        continue # this is most likely a normal php file
      elif sus_file.find("\\") != -1:
        matching_logs.append(log) # a backwards slash is super sus, could be obfuscated malicious commands
      else:
        matching_logs.append(log)
    return matching_logs

