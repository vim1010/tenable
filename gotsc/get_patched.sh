#!/bin/bash

go run . | jq '
  .response.results[] | {
    name: .name,
    id: .pluginID,
    desc: .severity.description,
    ips: .hosts[].iplist
  }
'
