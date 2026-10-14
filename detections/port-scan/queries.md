# Elasticsearch validation queries

Run in Kibana Dev Tools against the lab's `fortigate-v2-*` indices. Lab source: Kali `10.10.20.10`; lab destination: Ubuntu `10.10.10.20`. The pipeline maps `srcip`, `dstip`, and `dstport` to ECS `source.ip`, `destination.ip`, and `destination.port`.

## Slow scan: event count, distinct ports, first and last timestamps

```http
GET fortigate-v2-*/_search
{
  "size": 0,
  "track_total_hits": true,
  "query": {
    "bool": {
      "filter": [
        { "term": { "source.ip": "10.10.20.10" } },
        { "term": { "destination.ip": "10.10.10.20" } },
        { "range": { "destination.port": { "gte": 1, "lte": 100 } } },
        { "range": { "@timestamp": {
          "gte": "2026-10-14T21:40:04.110Z",
          "lte": "2026-10-14T21:41:05.000Z"
        } } }
      ]
    }
  },
  "aggs": {
    "unique_ports": {
      "cardinality": { "field": "destination.port", "precision_threshold": 40000 }
    },
    "first_event": { "min": { "field": "@timestamp", "format": "strict_date_time" } },
    "last_event": { "max": { "field": "@timestamp", "format": "strict_date_time" } },
    "ports_observed": { "terms": { "field": "destination.port", "size": 100 } }
  }
}
```

Compare `hits.total.value` with the recorded 111 matching events and `aggregations.unique_ports.value` with 100. Subtract the min/max numeric values (epoch milliseconds) to obtain `60890` ms. Cardinality is approximate; the port-range restriction and 100-bucket terms aggregation allow inspection of all possible ports in this test. Verify retained data and the actual test filters before expecting identical counts; these bounds alone do not exclude unrelated concurrent traffic between the same hosts.

The query intentionally does not restrict action to `deny`. Inspect `subtype=forward`, `action=server-rst`, `policyid=2`, and `policyname=ATTACKER-to_LAN` in matching documents. If adding exact filters for vendor strings, check mappings first: `kv` may produce `text` with a `.keyword` subfield rather than a directly searchable keyword. `policyid` may also be a string rather than a number.

## Fast scan

Reuse the same query with the fast run's actual UTC start/end bounds. Do not reuse the slow run's time range. The recorded result is 100 matching events, 100 unique destination ports, and about 10 ms between min/max timestamps; absolute fast-run timestamps are not available in this writeup.

## Review the mapping before adding policy/action filters

```http
GET fortigate-v2-*/_field_caps?fields=source.ip,destination.ip,destination.port,@timestamp,subtype,subtype.keyword,action,action.keyword,policyid,policyid.keyword,policyname,policyname.keyword
```

Confirm IP, numeric port, date, and aggregatable field mappings across the selected indices. These are investigation queries, not an installed detection rule. Validate scheduling, look-back, grouping and deduplication separately in the detection engine.
