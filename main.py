import os
import logging
import argparse
from typing import List
from src.analyzer import LogAnalyzer
from src.extractor import LogExtractor
from src.common.constants import DEFAULT_METHODS, DEFAULT_STATUS

logger = logging.getLogger(__name__)

def get_formatted_number(num: str) -> int:
  return "{:,}".format(num)

def get_logs(path: str) -> List[str]:
  if not os.path.exists(path):
    raise ValueError(f"File {path} does not exist")
  
  with open(path, 'r') as content:
    return [line.split("\n")[0] for line in content.readlines()]

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
  
  if len(logs) > max_logs and verbose is False:
    logs = logs[:max_logs]
    logs.append(f"... ({get_formatted_number(count - max_logs)} more)")
  else:
    logs.append(f"\n\n(Total: {get_formatted_number(len(logs))})")


  if len(logs) > 0:
    logs = "\n".join(logs)
    logs = f"Logs:\n{logs}"
  else:
    logs = "No logs found"

  return f"Title: {title}\nDescription: {description}\n\n{logs}"

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    parser = argparse.ArgumentParser(prog="Basset",description="Analyze your Nginx logs")
    parser.add_argument("-a", "--analysis", default="all", choices=['all', 'methods', 'status', 'paths'], help="The type of analysis to perform (defaults to 'all')")
    parser.add_argument("-f", "--file", required=True, help="Path to the log file")
    parser.add_argument("-s", "--status", default=DEFAULT_STATUS, help="Specify normal HTTP status codes comma-separated")
    parser.add_argument("-m", "--methods", default=DEFAULT_METHODS, help="Specify normal HTTP methods comma-separated")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show extensive reports")
    parser.add_argument("-d", "--debug", action="store_true", help="Show debug logs")

    args = parser.parse_args()
    analysis = args.analysis
    status_codes = args.status.split(",")
    methods = args.methods.split(",")
    verbose = args.verbose
    debug = args.debug

    if debug:
      logger.setLevel(logging.DEBUG)
      logger.debug(f"Config - Analysis: {analysis}")
      logger.debug(f"Config - Approved status: {status_codes}")
      logger.debug(f"Config - Approved methods: {methods}")
      logger.debug(f"Config - Verbose: {verbose}")
      logger.debug(f"Config - Debug: {debug}")

    try:
      analyzer = LogAnalyzer(logs=get_logs(args.file), verbose=verbose)
      reports = []

      if analysis == "all" or analysis == "methods":
        reports.append(report(
            title="Suspicious Methods",
            description=f"Logs with HTTP methods that are not {','.join(methods)}",
            logs=analyzer.find_logs_with_approved_methods(approved_methods=methods, inverse=True),
            verbose=verbose
        ))

      if analysis == "all" or analysis == "status":
        reports.append(report(
            title="Suspicious Status",
            description=f"Logs with HTTP status codes that are not {','.join(status_codes)}",
            logs=analyzer.find_logs_with_approved_status(approved_status_codes=status_codes, inverse=True),
            verbose=verbose
        ))

      if analysis == "all" or analysis == "paths":
        reports.append(report(
            title="Suspicious Paths",
            description=f"Logs with suspicious paths",
            logs=analyzer.find_sus_paths(),
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