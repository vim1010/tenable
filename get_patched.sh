#!/bin/bash

./etl.pl analysis \
  --source-type=patched | jq '.response.results[] | {name: .name, desc: .severity.description, ips: .hosts[].iplist}'
