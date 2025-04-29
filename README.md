# lad-LogEntropyCalculator
Calculates Shannon entropy for specified log fields, highlighting fields with unusually low entropy that may indicate static or malicious patterns. - Focused on Implements simple anomaly detection algorithms (e.g., clustering, outlier detection) on pre-processed log data to identify unusual patterns that may indicate security incidents.  Focuses on detecting statistical anomalies in log event frequency and attributes.

## Install
`git clone https://github.com/ShadowStrikeHQ/lad-logentropycalculator`

## Usage
`./lad-logentropycalculator [params]`

## Parameters
- `--threshold`: Entropy threshold for anomaly detection. Fields with entropy below this value are flagged. Default: 0.5
- `--delimiter`: No description provided
- `--header`: Specify if the log file has a header row.  If not included, assume no header row

## License
Copyright (c) ShadowStrikeHQ
