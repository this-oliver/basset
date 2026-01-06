# Basset

[![CI](https://github.com/this-oliver/basset/actions/workflows/ci.yaml/badge.svg)](https://github.com/this-oliver/basset/actions/workflows/ci.yaml) [![CD](https://github.com/this-oliver/basset/actions/workflows/cd.yaml/badge.svg)](https://github.com/this-oliver/basset/actions/workflows/cd.yaml)

Analyze your Nginx logs for suspicious activity.

## Getting Started

Pre-requisites:

- Python 12+ installed

Setup environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
python3 -m pip install -r requirements.txt
```

## Usage

> [!TIP]
> If you are struggling with regex, you can use [regex101](https://regex101.com/) to test your regex patterns. The grep command uses PCRE regex, so make sure to select the correct flavor.

```bash
# basic
python3 src/main.py -f access.log

# get all logs with paths that are not '/foo/bar' or '/foo/baz'
python3 src/main.py -f access.log -p '/foo/bar' -p '/foo/baz'

# get all requests that are not POST or GET requests (notice the comma)
python3 src/main.py -f access.log -m 'POST,GET'

# get all requests that are not 200 or 301 status codes (notice the comma)
python3 src/main.py -f access.log -s '200,301'
```

By default, the script will look for the following patterns:

- paths that are not any of the following:
  - `/`
  - `/index.html`
  - `/index/foo/bar.html`
  - `/assets/fonts/font.otf`
  - `/assets/images/logo.webp`
  - `/favicon.ico`
- requests that are not GET requests
- requests that are not 200 or 301 status codes

For more options, run the script with the `-h` flag:

```bash
python3 src/main.py -h

#usage: Basset [-h] [-a {all,methods,status,paths}] -f FILE [-s STATUS] [-m METHODS] [-v] [-d]

#Analyze your Nginx logs

#options:
#  -h, --help            show this help message and exit
#  -a {all,methods,status,paths}, --analysis {all,methods,status,paths}
#                        The type of analysis to perform (defaults to 'all')
#  -f FILE, --file FILE  Path to the log file
#  -s STATUS, --status STATUS
#                        Specify normal HTTP status codes comma-separated
#  -m METHODS, --methods METHODS
#                        Specify normal HTTP methods comma-separated
#  -v, --verbose         Show extensive reports
#  -d, --debug           Show debug logs
```

## Contribution

the repository is open for contributions as long as they meet the following criteria:

- code changes are readable above all else (that includes performance)
- [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/) for transparency and traceability
- pull request passes all checks
