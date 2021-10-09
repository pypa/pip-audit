import pip_audit.format as format


def test_columns(vuln_data):
    columns_format = format.ColumnsFormat(True)
    expected_columns = """Package Version ID     Affected Versions Description
------- ------- ------ ----------------- ------------------------
foo     1.0     VULN-0 1.1,1.4           The first vulnerability
foo     1.0     VULN-1 1.0               The second vulnerability
bar     0.1     VULN-2                   The third vulnerability"""
    assert columns_format.format(vuln_data) == expected_columns
