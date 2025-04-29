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

        df = pd.read_csv(log_file, delimiter=delimiter, usecols=fields, header=header_row, encoding='utf-8', error_bad_lines=False)

        #Rename columns if header is not present
        if header_row is None:
            df.columns = fields

        logging.info(f"Dataframe loaded successfully with {len(df)} rows.")

        for field in fields:
            if field not in df.columns:
                logging.error(f"Field '{field}' not found in the log file. Available fields are: {df.columns.tolist()}")
                print(f"Error: Field '{field}' not found in the log file. Check log file and field names.") #Provide user feedback
                return

        results = {}
        for field in fields:
            entropy = calculate_shannon_entropy(df[field])
            if entropy is not None:
                results[field] = entropy
                logging.info(f"Entropy for field '{field}': {entropy}")

                if entropy < threshold:
                    print(f"Anomaly detected: Field '{field}' has unusually low entropy ({entropy:.2f}). This may indicate a static or malicious pattern.")
                else:
                    print(f"Field '{field}' entropy: {entropy:.2f}")

    except FileNotFoundError:
        logging.error(f"Log file not found: {log_file}")
        print(f"Error: Log file not found: {log_file}. Please check the file path.") #User feedback
    except pd.errors.EmptyDataError:
        logging.error(f"Log file is empty: {log_file}")
        print(f"Error: Log file is empty: {log_file}.") #User Feedback
    except pd.errors.ParserError as e:
        logging.error(f"Error parsing log file: {e}")
        print(f"Error: Could not parse log file.  Check the delimiter and ensure the file is properly formatted. Detailed Error: {e}") #User feedback
    except ValueError as e:
         logging.error(f"ValueError: {e}")
         print(f"Error: ValueError - {e}. Check the log file and command-line arguments.")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        print(f"An unexpected error occurred: {e}. Check the logs for more details.") #User feedback


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

    analyze_log_file(args.log_file, args.fields, args.delimiter, args.threshold, args.header)

if __name__ == "__main__":
    main()