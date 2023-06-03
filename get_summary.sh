#!/bin/bash

./etl.pl analysis \
  --source-type=cumulative | jq '
      .response.results[] | {
        name: .name,
        id: .pluginID,
        desc: .severity.description,
        ips: .hosts[].iplist
      }
  '
