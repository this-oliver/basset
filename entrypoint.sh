#!/bin/env bash

# Define default values
DEFAULT_NORMAL_METHODS="GET"
DEFAULT_NORMAL_PATH="\/((fonts|images|favicon\.[a-zA-Z]+)(\/.*)+)?(\?[0-9a-zA-Z]+=[0-9a-zA-Z]+(\&[0-9a-zA-Z]+=[0-9a-zA-Z]+)*)?"
DEFAULT_NORMAL_STATUS="200,301"
DEFAULT_MAX_SUS_IPS_NUM=10
DEFAULT_MAX_SUS_REQS_NUM=10

usage() {
  echo "Usage: $0 <log_file> [OPTIONS]"
  echo "Options:"
  echo "  -p, --path <path>             Specify normal paths regex. Use https://regex101.com if you are strugling. (default: $DEFAULT_NORMAL_PATH)"
  echo "  -m, --methods <methods>       Specify normal HTTP methods comma-separated (default: $DEFAULT_NORMAL_METHODS)"
  echo "  -s, --status <status>         Specify normal HTTP status codes comma-separated (default: $DEFAULT_NORMAL_STATUS)"
  echo "  -i, --max-sus-ips <number>    Specify max suspicious IPs to show. Use -1 to show all and 0 to show none (default: $DEFAULT_MAX_SUS_IPS_NUM)"
  echo "  -r, --max-sus-reqs <number>   Specify max suspicious requests to show. Must be greater than 0 (default: $DEFAULT_MAX_SUS_REQS_NUM)"
  echo "  -h, --help                    Show this help message"
  echo "Example:"
  echo "  show paths that are not specifically '/foo/bar' or '/foo/baz':"
  echo "      $0 access.log -p '\/foo\/(bar|baz)'"
  echo ""
  echo "  show paths that are not POST requests:"
  echo "      $0 access.log -m 'POST'"
  echo ""
  echo "  show paths that are not 200 or 301 status codes:"
  echo "      $0 access.log -s '200,301'"
  echo ""
  echo "  show paths that are not POST requests with 400 status code:"
  echo "      $0 access.log -m 'GET' -s '400'"
  echo ""
  echo "  show top 50 suspicious IPs and 100 suspicious requests:"
  echo "      $0 access.log -i 50 -r 100"
  echo ""
  echo "  show all suspicious IPs:"
  echo "      $0 access.log -i -1"
}

convert_comma_to_regex() {
  local input="$1"
  local output=""

  # Convert comma-separated values to regex
  IFS=',' read -ra ADDR <<< "$input"
  for i in "${ADDR[@]}"; do
    if [[ -z "$output" ]]; then
      output="$i"
    else
      output+="|$i"
    fi
  done

  echo "$output"
}

log_error() {
  echo -e "\033[31mError: $1\033[0m"
}

main() {
  local LOG_FILE="$1"
  local NORMAL_PATH_REGEX="$2"
  local NORMAL_METHODS_REGEX="$3"
  local NORMAL_STATUS_REGEX="$4"
  local MAX_SUS_IPS_NUM="$5"
  local MAX_SUS_REQS_NUM="$6"

  # Check if log file exists
  if [ ! -f "$LOG_FILE" ]; then
    log_error "Log file $LOG_FILE not found!"
    exit 1
  fi

  # Define regex for normal requests
  REGEX="($NORMAL_METHODS_REGEX) ($NORMAL_PATH_REGEX) .* ($NORMAL_STATUS_REGEX) "

  # Extract suspicious requests
  SUS_REQUESTS=$(grep -vE "$REGEX" "$LOG_FILE")

  # Print top suspicious IPs
  if [[ "$MAX_SUS_IPS_NUM" -ne 0 ]]; then
    echo "=== Top $MAX_SUS_IPS_NUM Suspicious IPs ==="
    if [[ "$MAX_SUS_IPS_NUM" -lt 0 ]]; then
      echo "$SUS_REQUESTS" | awk '{print $1}' | sort | uniq -c | sort -nr | awk '{printf "%-8s %-15s\n", $1, $2}'
    elif [[ "$MAX_SUS_IPS_NUM" -gt 0 ]]; then
      echo "$SUS_REQUESTS" | awk '{print $1}' | sort | uniq -c | sort -nr | tail -n "$MAX_SUS_IPS_NUM" | awk '{printf "%-8s %-15s\n", $1, $2}'
    fi
  fi
  
  # Print table header
  echo -e "\n=== Suspicious Requests (showing latest $MAX_SUS_REQS_NUM) ==="
  printf "%-16s %-8s %-6s %-40s %-20s\n" "IP" "Method" "Status" "Path" "User-Agent"
  printf "=%.0s" {1..90}
  echo ""

  # Print table rows (format and print the requests)
  echo "$SUS_REQUESTS" | tail -"$MAX_SUS_REQS_NUM" | awk '{
    # Extract fields (adjust based on your exact log format)
    ip = $1;
    timestamp = $4 " " $5; # Adjust based on your log format
    gsub(/[\[\]]/, "", timestamp); # Remove square brackets
    method = substr($6, 2);
    path = $7;
    status = $9;
    ua = "";
    
    # Extract User-Agent (may vary by log format)
    for (i=12; i<=NF; i++) ua = ua " " $i;
    
    # Trim long fields
    if (length(path) > 38) path = substr(path, 1, 38) "...";
    if (length(ua) > 18) ua = substr(ua, 1, 18) "...";
    
    printf "%-16s %-20s %-8s %-6s %-40s %-20s\n", ip, timestamp, method, status, path, ua;
  }'
}

# Parse command line arguments
while [[ "$#" -gt 0 ]]; do
  case $1 in
    -p|--paths) NORMAL_PATH="$2"; shift ;;
    -m|--methods) NORMAL_METHODS="$2"; shift ;;
    -s|--status) NORMAL_STATUS="$2"; shift ;;
    -i|--max-sus-ips) MAX_SUS_IPS_NUM="$2"; shift ;;
    -r|--max-sus-reqs) MAX_SUS_REQS_NUM="$2"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) LOG_FILE="$1" ;;
  esac
  shift
done

# Check if log file is provided
if [ -z "$LOG_FILE" ]; then
  log_error "Log file is required."
  usage
  exit 1
fi

# Set default values if not provided
NORMAL_PATH="${NORMAL_PATH:-$DEFAULT_NORMAL_PATH}"
NORMAL_METHODS="${NORMAL_METHODS:-$DEFAULT_NORMAL_METHODS}"
NORMAL_STATUS="${NORMAL_STATUS:-$DEFAULT_NORMAL_STATUS}"
MAX_SUS_IPS_NUM="${MAX_SUS_IPS_NUM:-$DEFAULT_MAX_SUS_IPS_NUM}"
MAX_SUS_REQS_NUM="${MAX_SUS_REQS_NUM:-$DEFAULT_MAX_SUS_REQS_NUM}"

# Check if values are valid
if [[ ! "$NORMAL_METHODS" =~ ^[a-zA-Z,]+$ ]]; then
  log_error "Error: methods must be a comma-separated list of HTTP methods (current value: $NORMAL_METHODS)"
  echo usage
  exit 1
fi

if [[ ! "$NORMAL_STATUS" =~ ^[0-9,]+$ ]]; then
  log_error "Error: statuses must be a comma-separated list of HTTP status codes (current value: $NORMAL_STATUS)"
  echo usage
  exit 1
fi

if [[ ! "$MAX_SUS_IPS_NUM" =~ ^[-]?[0-9]+$ ]]; then
  log_error "Error: max sus ip addresses must be a number (current value: $MAX_SUS_IPS_NUM)"
  echo usage
  exit 1
fi

if [[ ! "$MAX_SUS_REQS_NUM" =~ ^[0-9]+$ || "$MAX_SUS_REQS_NUM" -lt 1 ]]; then
  log_error "Error: maz sus reqs must be a number greater than or equal to 1 (current value: $MAX_SUS_REQS_NUM)"
  echo usage
  exit 1
fi

# Convert comma-separated lists to regex
NORMAL_METHODS_REGEX=$(convert_comma_to_regex "$NORMAL_METHODS")
NORMAL_STATUS_REGEX=$(convert_comma_to_regex "$NORMAL_STATUS")

# Convert characters to uppercase
NORMAL_METHODS_REGEX=$(echo "$NORMAL_METHODS_REGEX" | tr '[:lower:]' '[:upper:]')

# Call the main function
main "$LOG_FILE" "$NORMAL_PATH" "$NORMAL_METHODS_REGEX" "$NORMAL_STATUS_REGEX" "$MAX_SUS_IPS_NUM" "$MAX_SUS_REQS_NUM"

# End of script