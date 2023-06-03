#!/bin/bash

tsc_url="$TSC_URL"
tsc_key="$TSC_KEY"
tsc_secret="$TSC_SECRET"
api_header="x-apikey: accesskey=$tsc_key; secretkey=$tsc_secret;"
content_header='content-type: application/json'

curl \
  -s \
  -H "$api_header" \
  -H "$content_header" \
  -d '{
    "query": {
      "tool": "vulnipsummary",
      "endOffset": 1000,
      "startOffset": 0,
      "type": "vuln",
      "filters": []
    },
    "type": "vuln",
    "sourceType": "patched"
  }' \
  "$tsc_url/rest/analysis" | jq '
    .response.results[] | {
      name: .name,
      id: .pluginID,
      desc: .severity.description,
      ips: .hosts[].iplist
    }
  '
