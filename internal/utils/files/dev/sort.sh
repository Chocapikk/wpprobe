#!/bin/bash

jq -cn '[inputs | to_entries[] | {plugin: .key, endpoint: .value[]} ]' scanned_plugins.json > endpoints_by_plugin.json

jq '[group_by(.endpoint)[] | select(length > 1) | .[0].endpoint]' endpoints_by_plugin.json > common_endpoints.json

jq --slurpfile common common_endpoints.json '
  to_entries
  | map(
      (.value - $common) as $filtered
      | if ($filtered | length) > 0 then
          {(.key): $filtered}
        else
          {(.key): .value}
        end
    )
  | add
  | to_entries[]
  | {(.key): .value}
' -c scanned_plugins.json > cleaned_file.json

cat common_endpoints.json

rm endpoints_by_plugin.json common_endpoints.json