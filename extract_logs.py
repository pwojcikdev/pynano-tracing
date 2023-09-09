#!/usr/bin/env python3

import concurrent.futures
import json
import os
import re
from pathlib import Path

import docker
import environs
from tqdm import tqdm

env = environs.Env()
env.read_env()

# prefix for all docker container names
PREFIX = env("PREFIX", default="fullnet")

DUMP_DIRNAME = "/data-raid/log-dumps"


client = docker.from_env()

LOG_PATTERN = r"\[(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\] \[(?P<component>\w+)\] \[(?P<level>\w+)\] (?P<payload>.+)"


def parse_log_line(line):
    matches = re.fullmatch(LOG_PATTERN, line)
    if not matches:
        return None
    return matches.groupdict()


TRACE_PATTERN = r"\"(?P<tag>.*?)\" (?P<data>.+)"


def parse_trace_line(line):
    matches = re.fullmatch(TRACE_PATTERN, line)
    if not matches:
        return None
    return matches.groupdict()


NAME_PATTERN = rf"^{re.escape(PREFIX)}_node-node-"


def fix_name(name):
    return re.sub(NAME_PATTERN, "", name)


def extract_logs(container):
    # print("Extracting logs from:", container.name)

    runid = container.labels["runid"]
    assert len(runid) > 0

    print(f"Extracting logs from: {container.name} ({runid})")

    BASE_DIR = Path(DUMP_DIRNAME) / runid / fix_name(container.name)
    os.makedirs(BASE_DIR, exist_ok=True)

    print(f"Extracting logs to: {BASE_DIR}")

    f = (BASE_DIR / "full.log").open("w")
    f_full = (BASE_DIR / "full.log.json").open("w")

    log_files = {}

    def log_file(component, tag):
        key = f"{component}-{tag}"
        if key not in log_files:
            log_files[key] = (BASE_DIR / f"{component}-{tag}.log.json").open("w")
        return log_files[key]

    for line in tqdm(container.logs(stream=True), desc="Processing logs"):
        line = line.decode("utf-8").strip()
        # print(line)

        parsed = parse_log_line(line)
        # print(parsed)

        if not parsed:
            # print("WARNING: Not parsed:", line)
            continue

        log_time = parsed["time"]
        log_component = parsed["component"]
        log_level = parsed["level"]
        log_payload = parsed["payload"]

        # f.write(line)
        # f.write("\n")

        json_line_full = rf'tstamp: "{log_time}", component: "{log_component}", level: "{log_level}", payload: "{log_payload}"'
        f_full.write(f"{{ {json_line_full} }}\n")

        if log_level == "trace":
            # print("TRACE:", parsed["payload"])

            trace_parsed = parse_trace_line(parsed["payload"])
            assert trace_parsed is not None
            # print(trace_parsed)

            trace_tag = trace_parsed["tag"]
            trace_data = trace_parsed["data"]

            json_line = rf'tstamp: "{log_time}", {trace_data}'
            # print(json_line)

            fl = log_file(log_component, trace_tag)
            fl.write(f"{{ {json_line} }}\n")

        # print()
        pass


def multiprocessing_handler(container_id):
    container = client.containers.get(container_id)
    extract_logs(container)


def main():
    os.makedirs(DUMP_DIRNAME, exist_ok=True)

    containers = client.containers.list(all=True, filters={"name": f"{PREFIX}_node-"})

    with concurrent.futures.ProcessPoolExecutor() as executor:
        executor.map(multiprocessing_handler, [c.id for c in containers])

        # break

    pass


if __name__ == "__main__":
    main()
