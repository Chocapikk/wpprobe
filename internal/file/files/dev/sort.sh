#!/bin/bash

jq -s '[.[] | to_entries[] | {plugin: .key, endpoint: .value[]} ]' scanned_plugins.json > endpoints_by_plugin.json

jq '[group_by(.endpoint)[] | select(length > 1) | .[0].endpoint]' endpoints_by_plugin.json > common_endpoints.json

jq -s --slurpfile common common_endpoints.json '
  map(
    to_entries[0] as $entry |
    $entry.value as $orig |
    ($orig - $common[0]) as $filtered |
    if ($filtered | length) > 0 then
      {($entry.key): $filtered}
    else
      {($entry.key): $orig}
    end
  )
  | .[]
' -c scanned_plugins.json > cleaned_file.jsonl

cat common_endpoints.json

rm endpoints_by_plugin.json common_endpoints.json
