import pip_audit.format as format

from .vuln_data import TEST_VULN_DATA


def test_columns():
    columns_format = format.ColumnsFormat()
    expected_columns = """Package Version ID     Description              Affected Versions
------- ------- ------ ------------------------ ------------------------------------
foo     1.0     VULN-0 The first vulnerability  (0.9 => fix: 1.1), (N/A => fix: 1.4)
foo     1.0     VULN-1 The second vulnerability (0.5 => fix: 1.0)
bar     0.1     VULN-2 The third vulnerability  (0.1 => fix: N/A)"""
    assert columns_format.format(TEST_VULN_DATA) == expected_columns
