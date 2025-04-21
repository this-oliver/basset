# basset

A bash script that reads your nginx access logs and generates a report of suspicious activity.

## usage

> [!TIP]
> If you are struggling with regex, you can use [regex101](https://regex101.com/) to test your regex patterns. The grep command uses PCRE regex, so make sure to select the correct flavor.

```bash
# basic
bash entrypoint.sh <log_file>

# get all requests that are not specifically '/foo/bar' or '/foo/baz' (use regex)
bash entrypoint.sh access.log -p '\/foo\/(bar|baz)'

# get all requests that are not POST or GET requests (notice the comma)
bash entrypoint.sh access.log -m 'POST,GET'

# get all requests that are not 200 or 301 status codes (notice the comma)
bash entrypoint.sh access.log -s '200,301'
```

For more options, run the script with the `-h` flag:

```bash
bash entrypoint.sh -h
```

## contribution

the repository is open for contributions as long as they meet the following criteria:

- code changes are readable above all else (that includes performance)
- [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/) for transparency and traceability
- pull request passes all checks
