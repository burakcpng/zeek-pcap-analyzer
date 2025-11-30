import json
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    import pandas as pd  # type: ignore
except ModuleNotFoundError:
    class _Series:
        def __init__(self, data):
            self.data = list(data)

        def __eq__(self, other):
            return _Series([value == other for value in self.data])

        def __gt__(self, other):
            return _Series([value > other for value in self.data])

        @property
        def str(self):
            return _StringMethods(self)

        def fillna(self, value):
            return _Series([value if item is None else item for item in self.data])

        def __iter__(self):
            return iter(self.data)

        def __len__(self):
            return len(self.data)

        def __getitem__(self, index):
            return self.data[index]

        def __add__(self, other):
            if isinstance(other, _Series):
                return _Series([left + right for left, right in zip(self.data, other.data)])
            return _Series([value + other for value in self.data])

        __radd__ = __add__

    class _StringMethods:
        def __init__(self, series):
            self.series = series

        def len(self):
            return _Series([len(item) if item is not None else 0 for item in self.series.data])

        def contains(self, pattern, case=False, na=False):
            def matches(value):
                if value is None:
                    return na
                haystack = value if case else str(value).lower()
                needle = pattern if case else str(pattern).lower()
                return needle in haystack

            return _Series([matches(item) for item in self.series.data])

    class _DataFrame:
        def __init__(self, records=None, columns=None):
            records = records or []
            self._records = [dict(record) for record in records]
            if columns is None and records:
                columns = list(records[0].keys())
            self.columns = columns or []

        @property
        def empty(self):
            return len(self._records) == 0

        def __len__(self):
            return len(self._records)

        def __getitem__(self, key):
            if isinstance(key, str):
                return _Series([record.get(key) for record in self._records])
            if isinstance(key, list):
                return _DataFrame(
                    [
                        {column: record.get(column) for column in key}
                        for record in self._records
                    ],
                    columns=key,
                )
            mask = list(key.data if isinstance(key, _Series) else key)
            filtered = [record for record, keep in zip(self._records, mask) if keep]
            return _DataFrame(filtered, columns=self.columns)

        def __setitem__(self, key, value):
            values = value.data if isinstance(value, _Series) else value
            for record, item_value in zip(self._records, values):
                record[key] = item_value
            if key not in self.columns:
                self.columns.append(key)

        def to_dict(self, orient="records"):
            if orient != "records":
                raise ValueError("Only 'records' orient is supported in stub")
            return [dict(record) for record in self._records]

    def _to_numeric(values, errors="raise"):
        numeric_values = []
        for value in values:
            try:
                numeric_values.append(float(value))
            except (TypeError, ValueError):
                if errors == "coerce":
                    numeric_values.append(None)
                else:
                    raise
        return _Series(numeric_values)

    stub = types.ModuleType("pandas")
    stub.DataFrame = _DataFrame
    stub.Series = _Series
    stub.to_numeric = _to_numeric
    sys.modules["pandas"] = stub
    pd = stub

from zeek_pcap_analyzer import ZeekPCAPAnalyzer


def test_analyze_suspicious_connections_detects_port_and_high_transfer():
    analyzer = ZeekPCAPAnalyzer()
    conn_df = pd.DataFrame(
        [
            {
                "id.orig_h": "192.168.1.10",
                "id.resp_h": "10.0.0.1",
                "id.resp_p": 22,
                "orig_bytes": 1_000,
                "resp_bytes": 500,
            },
            {
                "id.orig_h": "192.168.1.11",
                "id.resp_h": "10.0.0.2",
                "id.resp_p": 443,
                "orig_bytes": 8_000_000,
                "resp_bytes": 8_000_000,
            },
        ]
    )

    suspicious = analyzer.analyze_suspicious_connections(conn_df)
    suspicious_by_type = {item["type"]: item for item in suspicious}

    assert len(suspicious) == 2
    port_activity = suspicious_by_type["Suspicious Port Activity"]
    assert port_activity["count"] == 1
    assert port_activity["details"][0]["id.resp_p"] == 22

    high_transfer = suspicious_by_type["High Data Transfer"]
    assert high_transfer["count"] == 1
    assert high_transfer["details"][0]["total_bytes"] >= 10_000_000


def test_analyze_suspicious_connections_returns_empty_when_no_matches():
    analyzer = ZeekPCAPAnalyzer()
    benign_df = pd.DataFrame(
        [
            {
                "id.orig_h": "192.168.1.20",
                "id.resp_h": "10.0.0.3",
                "id.resp_p": 80,
                "orig_bytes": 500,
                "resp_bytes": 600,
            }
        ]
    )

    suspicious = analyzer.analyze_suspicious_connections(benign_df)

    assert suspicious == []


def test_analyze_dns_activity_detects_long_queries_and_keywords():
    analyzer = ZeekPCAPAnalyzer()
    dns_df = pd.DataFrame(
        [
            {"id.orig_h": "1.1.1.1", "query": "a" * 60},
            {"id.orig_h": "2.2.2.2", "query": "malware-site.com"},
        ]
    )

    suspicious = analyzer.analyze_dns_activity(dns_df)
    suspicious_by_type = {item["type"]: item for item in suspicious}

    assert len(suspicious) == 2
    tunneling = suspicious_by_type["Potential DNS Tunneling"]
    assert tunneling["count"] == 1
    assert len(tunneling["details"]) == 1
    assert tunneling["details"][0]["query"].startswith("a")

    keyword = suspicious_by_type["Suspicious Domain Query"]
    assert keyword["count"] == 1
    assert keyword["details"][0]["query"] == "malware-site.com"


def test_analyze_dns_activity_returns_empty_for_no_records():
    analyzer = ZeekPCAPAnalyzer()
    empty_df = pd.DataFrame(columns=["id.orig_h", "query"])

    suspicious = analyzer.analyze_dns_activity(empty_df)

    assert suspicious == []


def test_generate_report_summarizes_counts(tmp_path):
    analyzer = ZeekPCAPAnalyzer()
    suspicious_activities = [
        {
            "type": "Suspicious Port Activity",
            "description": "Connections to restricted ports",
            "count": 2,
            "details": [{"id.orig_h": "192.168.1.1", "id.resp_p": 22}],
        },
        {
            "type": "Suspicious Domain Query",
            "description": "Malware domain queries",
            "count": 1,
            "details": [{"id.orig_h": "2.2.2.2", "query": "malware-site.com"}],
        },
    ]

    report_path = tmp_path / "report.json"
    report = analyzer.generate_report(suspicious_activities, report_path)

    assert report["total_suspicious_activities"] == 2
    assert report["summary"]["total_suspicious_events"] == 3
    assert report["summary"]["activity_breakdown"] == {
        "Suspicious Port Activity": 2,
        "Suspicious Domain Query": 1,
    }

    with report_path.open() as handle:
        persisted = json.load(handle)

    assert persisted["summary"] == report["summary"]
    assert persisted["total_suspicious_activities"] == report["total_suspicious_activities"]
