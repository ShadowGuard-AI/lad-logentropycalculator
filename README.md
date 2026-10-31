![Banner](banner.png)

# lad-LogEntropyCalculator
Calculates Shannon entropy for specified log fields, highlighting fields with unusually low entropy that may indicate static or malicious patterns. - Focused on Implements simple anomaly detection algorithms (e.g., clustering, outlier detection) on pre-processed log data to identify unusual patterns that may indicate security incidents.  Focuses on detecting statistical anomalies in log event frequency and attributes.

## Install
`git clone https://github.com/ShadowStrikeHQ/lad-logentropycalculator`

## Usage
`python3 main.py [params] log_file fields`

## Parameters
- `log_file`: Path to the log file. Required.
- `fields`: One or more log fields to analyze. Required. Without `--header`, the fields name the columns positionally, in order.
- `--threshold`: Entropy threshold for anomaly detection. Fields with entropy below this value are flagged. Default: 0.5
- `--delimiter`: Delimiter used in the log file. Default: comma (,)
- `--header`: Specify if the log file has a header row.  If not included, assume no header row

## License
Copyright (c) ShadowStrikeHQ
