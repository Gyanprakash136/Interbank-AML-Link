from pathlib import Path

import pandas as pd
import pytest

from app.evaluation.artifacts import sha256_file
from app.evaluation.dataset_validation import (
    DatasetSchemaError, normalize_chunk, profile_csv, read_chunks,
)

HEADER = ("Timestamp,From Bank,Account,To Bank,Account,Amount Received,Receiving Currency,"
          "Amount Paid,Payment Currency,Payment Format,Is Laundering")
GOOD1 = "2022/09/01 00:20,010,A1,020,B1,5000.00,US Dollar,5000.00,US Dollar,Wire,1"
GOOD2 = "2022/09/01 01:15,020,B1,010,A1,100.50,Euro,100.50,Euro,Credit Card,0"
BAD_TS = "2022/13/45 99:99,010,A1,020,B1,10,US Dollar,10,US Dollar,Wire,0"
BAD_TS_AND_AMT = "garbage,010,A1,020,B1,-5,US Dollar,-5,US Dollar,Wire,0"
NEG_AMT = "2022/09/01 02:00,010,A1,020,B1,-5,US Dollar,-5,US Dollar,Wire,0"
NAN_AMT = "2022/09/01 02:00,010,A1,020,B1,abc,US Dollar,abc,US Dollar,Wire,0"
NO_CUR = "2022/09/01 02:00,010,A1,020,B1,5,US Dollar,5,,Wire,0"
NO_BANK = "2022/09/01 02:00,,A1,020,B1,5,US Dollar,5,US Dollar,Wire,0"
BAD_LABEL = "2022/09/01 02:00,010,A1,020,B1,5,US Dollar,5,US Dollar,Wire,2"
ODD_CUR = "2022/09/01 03:00,010,A1,020,B1,5,Zorkmid,5,Zorkmid,ACH,0"


def write(tmp_path, rows, header=HEADER):
    p = tmp_path / "hs.csv"
    p.write_text(header + "\n" + "\n".join(rows) + "\n")
    return p


def test_rejects_with_single_priority_reason(tmp_path):
    p = write(tmp_path, [GOOD1, BAD_TS, BAD_TS_AND_AMT, NEG_AMT, NAN_AMT, NO_CUR, NO_BANK, BAD_LABEL, GOOD2])
    chunk = next(read_chunks(p))
    clean, rejected, _ = normalize_chunk(chunk)
    assert list(clean["row_number"]) == [0, 8]
    reasons = dict(zip(rejected["row_number"], rejected["reject_reason"]))
    assert reasons == {1: "bad_timestamp", 2: "bad_timestamp", 3: "bad_amount",
                       4: "bad_amount", 5: "missing_currency",
                       6: "missing_identifier", 7: "bad_label"}


def test_normalization_outputs(tmp_path):
    p = write(tmp_path, [GOOD1, GOOD2, ODD_CUR])
    clean, rejected, unmapped = normalize_chunk(next(read_chunks(p)))
    assert rejected.empty
    assert list(clean["timestamp_iso"]) == ["2022-09-01T00:20:00Z", "2022-09-01T01:15:00Z", "2022-09-01T03:00:00Z"]
    assert list(clean["currency"]) == ["USD", "EUR", "ZORKMID"]
    assert unmapped == {"Zorkmid"}
    assert list(clean["from_bank"]) == ["010", "020", "010"]  # leading zeros preserved
    assert list(clean["tx_type"]) == ["WIRE", "CREDIT_CARD", "ACH"]
    assert clean["is_laundering"].tolist() == [1, 0, 0]


def test_header_mismatch_raises(tmp_path):
    p = write(tmp_path, [GOOD1], header=HEADER.replace("Is Laundering", "Label"))
    with pytest.raises(DatasetSchemaError):
        next(read_chunks(p))
    with pytest.raises(DatasetSchemaError):
        profile_csv(p)


def test_profile_counts(tmp_path):
    p = write(tmp_path, [GOOD1, GOOD1, GOOD2, BAD_TS, ODD_CUR])
    prof = profile_csv(p, chunksize=2)  # also exercises chunk boundaries
    assert prof["row_count"] == 5
    assert prof["sha256"] == sha256_file(p)
    assert prof["label_counts"] == {"1": 2, "0": 3}
    assert prof["exact_duplicate_rows"] == 1
    assert prof["reject_counts"] == {"bad_timestamp": 1}
    assert prof["unmapped_currency_names"] == ["Zorkmid"]
    assert prof["payment_currency_counts"]["US Dollar"] == 3
    assert prof["distinct_banks"] == 2


def test_profile_is_chunk_size_independent(tmp_path):
    rows = [GOOD1, GOOD2, GOOD1, ODD_CUR, BAD_LABEL, GOOD2]
    p = write(tmp_path, rows)
    a, b = profile_csv(p, chunksize=1), profile_csv(p, chunksize=100)
    for k in a:
        assert a[k] == b[k], k
