import pip_audit._format as format


def test_columns(vuln_data):
    columns_format = format.ColumnsFormat(True)
    expected_columns = """Name Version ID     Fix Versions Description
---- ------- ------ ------------ ------------------------
foo  1.0     VULN-0 1.1,1.4      The first vulnerability
foo  1.0     VULN-1 1.0          The second vulnerability
bar  0.1     VULN-2              The third vulnerability"""
    assert columns_format.format(vuln_data) == expected_columns


def test_columns_no_desc(vuln_data):
    columns_format = format.ColumnsFormat(False)
    expected_columns = """Name Version ID     Fix Versions
---- ------- ------ ------------
foo  1.0     VULN-0 1.1,1.4
foo  1.0     VULN-1 1.0
bar  0.1     VULN-2"""
    assert columns_format.format(vuln_data) == expected_columns


def test_columns_skipped_dep(vuln_data_skipped_dep):
    columns_format = format.ColumnsFormat(False)
    expected_columns = """Name Version ID     Fix Versions
---- ------- ------ ------------
foo  1.0     VULN-0 1.1,1.4
Name Skip Reason
---- -----------
bar  skip-reason"""
    print(columns_format.format(vuln_data_skipped_dep))
    assert columns_format.format(vuln_data_skipped_dep) == expected_columns
