from cvsslib.vector import parse_vector, detect_vector, VectorError
from cvsslib import cvss2, cvss3
import argparse


def main():
    parser = argparse.ArgumentParser(description="Calculate CVSS scores from a vector")
    parser.add_argument('vector')
    parser.add_argument('-v', default=None, dest="version", type=int, help="CVSS version to use (default: autodetect)")
    args = parser.parse_args()

    module = None

    if args.version is not None:
        module = {2: cvss2, 3: cvss3}[args.version]

    try:
        results = parse_vector(args.vector, module)
    except VectorError as e:
        print("Error parsing vector: {0}".format(e.message))
    else:
        print("Base Score:\t{0}".format(results[0]))
        print("Temporal:\t{0}".format(results[1]))
        print("Environment:\t{0}".format(results[2]))


if __name__ == "__main__":
    main()