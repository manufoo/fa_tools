#!python3
import sys
import re
from collections import Counter

### VARS ###

pattern_ipv4 = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'

def get_log(filepath):
    logs = []
    with open(filepath) as f:
        logs = f.read()
    return logs

def get_adresses(raw_log):
    adresses = re.findall(pattern_ipv4, raw_log)
    return adresses

def filter_sus(ip_dict, amount):
    sus_ips = []
    for key, value in ip_dict.items():
        if value >= amount:
            entry = key, value
            sus_ips.append(entry)
    return sus_ips

def main():
    #args only for terminal use
    import argparse
    parser = argparse.ArgumentParser(description="Parse and analyse logs")
    #parser.add_argument("filepath", nargs="?", help="Path to file")
    parser.add_argument("-f", "--file", dest="filename", help="Path to logfile")
    parser.add_argument("-c", "--count", dest="count", help="Detection level")
    args = parser.parse_args()
    if len(sys.argv) <= 1:
        parser.print_help()
        sys.exit(1)
    if not args.filename:
        print("Filepath and Count required!")
        parser.print_help()
        sys.exit(1)

    mylog = get_log(args.filename)
    adresses = get_adresses(mylog)
    counted_adresses = Counter(adresses)
    results = filter_sus(counted_adresses, int(args.count))
    for item in results:
        pad_char = ' '
        message = f"Suspicious activity detected => {item[0]}: {item[1]} attempts!"
        print(message)


if __name__ == "__main__":
    main()
