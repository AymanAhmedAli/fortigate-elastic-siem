# Elasticsearch validation queries

Run these in Kibana Dev Tools against the lab's `fortigate-v2-*` indices.

Current lab sources used during validation:

- Kali: `10.10.20.10`
- Windows test host on attacker segment: `10.10.20.30`
- Ubuntu / Elastic target: `10.10.10.20`

The pipeline maps FortiGate fields to ECS `source.ip`, `destination.ip`, and `destination.port`.

## 1. Count unique destination ports and measure activity duration

```http
GET fortigate-v2-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "filter": [
        { "term": { "source.ip": "10.10.20.10" } },
        { "term": { "destination.ip": "10.10.10.20" } },
        { "range": { "@timestamp": {
          "gte": "START_TIME",
          "lte": "END_TIME"
        } } }
      ]
    }
  },
  "aggs": {
    "first_event": {
      "min": { "field": "@timestamp" }
    },
    "last_event": {
      "max": { "field": "@timestamp" }
    },
    "unique_destination_ports": {
      "cardinality": { "field": "destination.port" }
    }
  }
}
```

This query provides:

- total matching documents (`hits.total.value`)
- first event timestamp
- last event timestamp
- number of unique destination ports

Do not assume `document count == port count`. One connection attempt can generate more than one FortiGate log document.

## 2. Slow Nmap validation

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
      "cardinality": {
        "field": "destination.port",
        "precision_threshold": 40000
      }
    },
    "first_event": {
      "min": { "field": "@timestamp", "format": "strict_date_time" }
    },
    "last_event": {
      "max": { "field": "@timestamp", "format": "strict_date_time" }
    },
    "ports_observed": {
      "terms": { "field": "destination.port", "size": 100 }
    }
  }
}
```

Recorded result:

```text
Matching events: 111
Unique ports:    100
Duration:        60.89 seconds
```

## 3. PowerShell scanner validation

The Windows test host was temporarily moved to `10.10.20.30` so its traffic had to traverse FortiGate before reaching `10.10.10.20`.

```http
GET fortigate-v2-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "filter": [
        { "term": { "source.ip": "10.10.20.30" } },
        { "term": { "destination.ip": "10.10.10.20" } },
        { "range": { "@timestamp": {
          "gte": "2026-10-15T12:29:00Z",
          "lte": "2026-10-15T12:33:30Z"
        } } }
      ]
    }
  },
  "aggs": {
    "first_event": {
      "min": { "field": "@timestamp" }
    },
    "last_event": {
      "max": { "field": "@timestamp" }
    },
    "unique_destination_ports": {
      "cardinality": { "field": "destination.port" }
    }
  }
}
```

Recorded result:

```text
Total hits:               496
Unique destination ports: 100
First event:              2026-10-15T12:29:13.370Z
Last event:               2026-10-15T12:32:48.220Z
Duration:                 ~214.85 seconds
```

## 4. Unique ports per one-minute bucket

This query was used to understand whether the PowerShell scan met the threshold inside individual one-minute periods.

```http
GET fortigate-v2-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "filter": [
        { "term": { "source.ip": "10.10.20.30" } },
        { "term": { "destination.ip": "10.10.10.20" } },
        { "range": { "@timestamp": {
          "gte": "2026-10-15T12:29:00Z",
          "lte": "2026-10-15T12:33:30Z"
        } } }
      ]
    }
  },
  "aggs": {
    "per_minute": {
      "date_histogram": {
        "field": "@timestamp",
        "fixed_interval": "1m"
      },
      "aggs": {
        "unique_ports": {
          "cardinality": {
            "field": "destination.port"
          }
        }
      }
    }
  }
}
```

Recorded buckets:

| UTC minute | Documents | Unique ports |
|---|---:|---:|
| 12:29 | 107 | 22 |
| 12:30 | 138 | 31 |
| 12:31 | 145 | 32 |
| 12:32 | 106 | 24 |

Each bucket exceeded the live rule's `>= 20` unique-port threshold.

## 5. Relative time window for recent tests

When testing immediately after generating traffic, relative time avoids manual UTC/local-time conversion errors:

```http
GET fortigate-v2-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "filter": [
        { "term": { "source.ip": "10.10.20.10" } },
        { "term": { "destination.ip": "10.10.10.20" } },
        { "range": { "@timestamp": {
          "gte": "now-15m",
          "lte": "now"
        } } }
      ]
    }
  },
  "aggs": {
    "unique_destination_ports": {
      "cardinality": { "field": "destination.port" }
    }
  }
}
```

## 6. Mapping check

Before adding exact policy/action filters, confirm field types:

```http
GET fortigate-v2-*/_field_caps?fields=source.ip,destination.ip,destination.port,@timestamp,subtype,subtype.keyword,action,action.keyword,policyid,policyid.keyword,policyname,policyname.keyword
```

For FortiGate string fields created by `kv`, the exact-match field may be the direct field or a `.keyword` subfield depending on the index mapping.

## Investigation notes

- `200 OK` with `0 hits` means Elasticsearch executed the query successfully but no document matched all filters.
- Check time range, source, destination and index before changing the query logic.
- Kibana may display local time while Elasticsearch timestamps are stored/displayed as UTC (`Z`).
- The live detection rule is separate from these investigation queries. Scheduling, look-back, grouping, threshold and cardinality are configured in the Kibana Detection Engine.
