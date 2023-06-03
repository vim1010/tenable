#!/bin/bash

./etl.pl analysis \
  --source-type=patched | jq '
      .response.results[] | {
        name: .name,
        id: .pluginID,
        desc: .severity.description,
        ips: .hosts[].iplist
      }
  '
