from __future__ import annotations

import json

from parsers.cic_ids_parser import parse_cic_ids
from parsers.common_crawl_parser import parse_common_crawl
from parsers.dvwa_traffic_parser import parse_dvwa_traffic
from parsers.juiceshop_traffic_parser import parse_juiceshop_traffic
from parsers.modsec_crs_parser import parse_modsecurity_crs
from parsers.nvd_cve_parser import parse_nvd_cve_snapshot
from parsers.unsw_nb15_parser import parse_unsw_nb15


def test_parse_unsw_nb15_minimal(tmp_path) -> None:
    csv_path = tmp_path / "unsw.csv"
    csv_path.write_text(
        "proto,service,state,spkts,dpkts,sbytes,dbytes,attack_cat,label\n"
        "tcp,http,FIN,3,2,120,80,Normal,0\n"
        "tcp,http,CON,10,8,200,180,Exploits,1\n",
        encoding="utf-8",
    )
    rows = parse_unsw_nb15(tmp_path, max_rows=10)
    assert len(rows) == 2
    assert {row["label"] for row in rows} == {0, 1}


def test_parse_cic_ids_minimal(tmp_path) -> None:
    csv_path = tmp_path / "cic.csv"
    csv_path.write_text(
        "Flow Duration,Total Fwd Packets,Total Backward Packets,Flow Bytes/s,Label\n"
        "10,2,2,120.5,BENIGN\n"
        "100,40,12,5000.0,DoS Hulk\n",
        encoding="utf-8",
    )
    rows = parse_cic_ids(tmp_path, max_rows=10)
    assert len(rows) == 2
    assert rows[0]["label"] == 0
    assert rows[1]["label"] == 1


def test_parse_common_crawl_jsonl(tmp_path) -> None:
    file_path = tmp_path / "sample.jsonl"
    file_path.write_text(
        json.dumps({"method": "GET", "url": "https://example.com/search?q=chair"}) + "\n",
        encoding="utf-8",
    )
    rows = parse_common_crawl(tmp_path, max_rows=10)
    assert len(rows) == 1
    assert rows[0]["label"] == 0
    assert rows[0]["source"] == "CommonCrawl"


def test_parse_juiceshop_and_dvwa_traffic(tmp_path) -> None:
    js_dir = tmp_path / "juice"
    js_dir.mkdir()
    js_file = js_dir / "traffic.jsonl"
    js_file.write_text(
        json.dumps({"method": "GET", "path": "/rest/products/search", "category": "sqli", "label": 1}) + "\n",
        encoding="utf-8",
    )
    js_rows = parse_juiceshop_traffic(js_dir, max_rows=10)
    assert len(js_rows) == 1
    assert js_rows[0]["label"] == 1

    dvwa_dir = tmp_path / "dvwa"
    dvwa_dir.mkdir()
    dvwa_file = dvwa_dir / "traffic.jsonl"
    dvwa_file.write_text(
        json.dumps({"method": "POST", "path": "/vulnerabilities/sqli/", "label": 1, "category": "sqli"}) + "\n",
        encoding="utf-8",
    )
    dvwa_rows = parse_dvwa_traffic(dvwa_dir, max_rows=10)
    assert len(dvwa_rows) == 1
    assert dvwa_rows[0]["label"] == 1


def test_parse_modsecurity_crs(tmp_path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    conf = rules_dir / "REQUEST-942-APPLICATION-ATTACK-SQLI.conf"
    conf.write_text(
        "SecRule ARGS \"@rx (?i:(union select|sleep\\())\" \"id:942100,phase:2,deny,msg:'SQL Injection Attack',tag:'attack-sqli'\"\n",
        encoding="utf-8",
    )
    rows = parse_modsecurity_crs(tmp_path, max_rules=10)
    assert len(rows) == 1
    assert rows[0]["label"] == 1
    assert rows[0]["source"] == "ModSecurity-CRS"


def test_parse_nvd_snapshot(tmp_path) -> None:
    snapshot = tmp_path / "nvd.json"
    snapshot.write_text(
        json.dumps(
            {
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2025-1234",
                            "descriptions": [{"lang": "en", "value": "SQL injection in API endpoint"}],
                        }
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    rows = parse_nvd_cve_snapshot(snapshot, max_records=10)
    assert len(rows) == 1
    assert rows[0]["category"] == "sqli"
