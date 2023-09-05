#!/usr/bin/env python3

import json
import os
import re

import docker
import environs

env = environs.Env()
env.read_env()

# prefix for all docker container names
PREFIX = env("PREFIX", default="fullnet")

DUMP_DIRNAME = ".log-dumps"


client = docker.from_env()

LOG_PATTERN = r"\[(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\] \[(?P<component>\w+)\] \[(?P<level>\w+)\] (?P<payload>.+)"


def parse_log_line(line):
    """
    Parse a log line into a dict
    """
    matches = re.fullmatch(LOG_PATTERN, line)
    if not matches:
        return None
    return matches.groupdict()


TRACE_PATTERN = r"\"(?P<tag>.*?)\" (?P<data>.+)"


def parse_trace_line(line):
    """
    Parse a trace line into a dict
    """
    matches = re.fullmatch(TRACE_PATTERN, line)
    if not matches:
        return None
    return matches.groupdict()


# TO_JSON_PATTERN = r"(\w+):", r'"\1":'


# def parse_trace_data(payload):
#     """
#     Parse a trace data payload into a dict
#     """
#     converted = re.sub(TO_JSON_PATTERN[0], TO_JSON_PATTERN[1], payload)
#     return json.loads("{" + converted + "}")


def extract_logs(container):
    """
    Extract logs from a container
    """
    print("Extracting logs from:", container.name)

    BASE_DIR = f"{DUMP_DIRNAME}/{container.name}"
    os.makedirs(BASE_DIR, exist_ok=True)

    f = open(f"{BASE_DIR}/full.log", "w")

    log_files = {}

    def log_file(component, tag):
        key = f"{component}-{tag}"
        if key not in log_files:
            log_files[key] = open(f"{BASE_DIR}/{component}-{tag}.log.json", "w")
        return log_files[key]

    for line in container.logs(stream=True):
        line = line.decode("utf-8").strip()
        # print(line)

        parsed = parse_log_line(line)
        # print(parsed)

        if not parsed:
            print("WARNING: Not parsed:", line)
            continue

        log_time = parsed["time"]
        log_component = parsed["component"]

        # f.write(line)
        # f.write("\n")

        if parsed["level"] == "trace":
            # print("TRACE:", parsed["payload"])

            trace_parsed = parse_trace_line(parsed["payload"])
            assert trace_parsed is not None
            # print(trace_parsed)

            # trace_data = parse_trace_data(trace_parsed["data"])
            # print("TRACE DATA:", trace_data)

            trace_tag = trace_parsed["tag"]
            trace_data = trace_parsed["data"]

            json_line = rf'tstamp: "{log_time}", {trace_data}'
            print(json_line)

            fl = log_file(log_component, trace_tag)
            fl.write(f"{{ {json_line} }}\n")

        print()


def main():
    os.makedirs(DUMP_DIRNAME, exist_ok=True)

    for container in client.containers.list(all=True, filters={"name": f"{PREFIX}_node-"}):
        print("Found node:", container.name)

        extract_logs(container)

    pass


if __name__ == "__main__":
    main()
