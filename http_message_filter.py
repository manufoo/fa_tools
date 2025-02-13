#!python3
import sys
import pyshark
import base64
from urllib.parse import unquote


def main():
    # args only for terminal use
    # import argparse

    # parser = argparse.ArgumentParser(description="http message filter")
    # parser.add_argument("filepath", nargs="?", help="Path to file")
    # args = parser.parse_args()
    if len(sys.argv) < 3:
        print("use script.py file encoding")
        sys.exit()

    filepath = sys.argv[1]
    encoding = sys.argv[2]

    cap = pyshark.FileCapture(filepath, display_filter="http")

    results = []

    for paket in cap:
        try:
            # try to decoded
            string = paket.http.request_uri
            to_decode = string.split("=", 1)[1]
            result = ""
            if encoding == "plain":
                result = to_decode
            elif encoding == "base64":
                result = base64.b64decode(unquote(to_decode)).decode("utf-8")
            elif encoding == "base16":
                result = base64.b16decode(unquote(to_decode)).decode("utf-8")

            # print(result)
            if "The next flag" in result or "The+next+flag" in result:
                # print(result)
                results.append((paket, result))

        except:
            continue

    for result in results:
        print(result[1])


if __name__ == "__main__":
    main()
