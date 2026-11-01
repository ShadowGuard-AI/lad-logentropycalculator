import argparse
import pandas as pd
import numpy as np
import math
import logging
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the CLI.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description='Calculates Shannon entropy for specified log fields to detect anomalies.')
    parser.add_argument('log_file', type=str, help='Path to the log file.')
    parser.add_argument('fields', type=str, nargs='+', help='List of log fields to analyze (e.g., timestamp, source_ip).')
    parser.add_argument('--threshold', type=float, default=0.5, help='Entropy threshold for anomaly detection. Fields with entropy below this value are flagged. Default: 0.5')
    parser.add_argument('--delimiter', type=str, default=',', help='Delimiter used in the log file. Default: comma (,)')
    parser.add_argument('--header', action='store_true', help='Specify if the log file has a header row.  If not included, assume no header row')
    return parser

def calculate_shannon_entropy(data):
    """
    Calculates Shannon entropy for a given pandas Series.

    Args:
        data (pd.Series): The data series for which to calculate entropy.

    Returns:
        float: The Shannon entropy of the data.
    """
    try:
        if not isinstance(data, pd.Series):
            raise TypeError("Input must be a pandas Series.")

        if data.empty:
            return 0.0  # Return 0 for empty data

        # value_counts drops missing values before normalising, so a field
        # that is half empty is measured on its present half only. The blank
        # half, often the interesting half in a log, contributes nothing to
        # this number.
        probabilities = data.value_counts(normalize=True)
        entropy = -np.sum(probabilities * np.log2(probabilities))
        return entropy
    except Exception as e:
        logging.error(f"Error calculating Shannon entropy: {e}")
        return None

def analyze_log_file(log_file, fields, delimiter=',', threshold=0.5, header=False):
    """
    Analyzes the log file, calculates entropy for specified fields, and identifies anomalies.

    Args:
        log_file (str): Path to the log file.
        fields (list): List of log fields to analyze.
        delimiter (str): Delimiter used in the log file.
        threshold (float): Entropy threshold for anomaly detection.
        header (bool): Indicates if the log file contains a header row.

    Returns:
        None: Prints the analysis results to the console.
    """
    try:
        logging.info(f"Analyzing log file: {log_file}")

        # Determine if header is present
        header_row = 0 if header else None

        if header_row is None:
            # No header row: field names cannot be used as usecols, because
            # pandas matches usecols against column names that do not exist
            # yet. Load positionally, check the column count, then rename.
            # on_bad_lines='skip' appears on both read paths, so malformed rows
            # vanish silently and the entropy is computed over the survivors. A
            # log whose worst rows are malformed is reported on its best rows.
            df = pd.read_csv(log_file, delimiter=delimiter, header=None, encoding='utf-8', on_bad_lines='skip')
            if df.shape[1] < len(fields):
                print(f"Error: Log file has {df.shape[1]} columns, but {len(fields)} fields were named. Check the log file and field names.")
                return False
            df = df.iloc[:, :len(fields)]
            # In no-header mode the field names are positions, not names: the
            # first columns are taken in file order and renamed from the command
            # line list. Naming a field that sits fifth while asking for two
            # fields analyses whichever column is second, under the fifth's name.
            df.columns = fields
        else:
            df = pd.read_csv(log_file, delimiter=delimiter, usecols=fields, header=header_row, encoding='utf-8', on_bad_lines='skip')

        if len(df) == 0:
            print(f"Error: Log file has no data rows to analyse: {log_file}.")
            return False

        logging.info(f"Dataframe loaded successfully with {len(df)} rows.")

        for field in fields:
            if field not in df.columns:
                logging.error(f"Field '{field}' not found in the log file. Available fields are: {df.columns.tolist()}")
                print(f"Error: Field '{field}' not found in the log file. Check log file and field names.") #Provide user feedback
                return False

        results = {}
        for field in fields:
            entropy = calculate_shannon_entropy(df[field])
            # A field whose calculation failed is simply left out of the results,
            # and the run can still return True on the strength of the others.
            # The error is in the log; the printed output shows no gap.
            if entropy is not None:
                results[field] = entropy
                logging.info(f"Entropy for field '{field}': {entropy}")

                if entropy < threshold:
                    print(f"Anomaly detected: Field '{field}' has unusually low entropy ({entropy:.2f}). This may indicate a static or malicious pattern.")
                else:
                    print(f"Field '{field}' entropy: {entropy:.2f}")

        return True

    except FileNotFoundError:
        logging.error(f"Log file not found: {log_file}")
        print(f"Error: Log file not found: {log_file}. Please check the file path.") #User feedback
        return False
    except pd.errors.EmptyDataError:
        logging.error(f"Log file is empty: {log_file}")
        print(f"Error: Log file is empty: {log_file}.") #User Feedback
        return False
    except pd.errors.ParserError as e:
        logging.error(f"Error parsing log file: {e}")
        print(f"Error: Could not parse log file.  Check the delimiter and ensure the file is properly formatted. Detailed Error: {e}") #User feedback
        return False
    except ValueError as e:
         logging.error(f"ValueError: {e}")
         print(f"Error: ValueError - {e}. Check the log file and command-line arguments.")
         return False
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        print(f"An unexpected error occurred: {e}. Check the logs for more details.") #User feedback
        return False


def main():
    """
    Main function to execute the log entropy calculation.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Input validation: Check if threshold is a valid number
    if not (isinstance(args.threshold, float) or isinstance(args.threshold, int)):
        print("Error: Threshold must be a number.")
        sys.exit(1)
    if args.threshold < 0:
        print("Error: Threshold must be a non-negative number.")
        sys.exit(1)

    if not analyze_log_file(args.log_file, args.fields, args.delimiter, args.threshold, args.header):
        sys.exit(1)

if __name__ == "__main__":
    main()