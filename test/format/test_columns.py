import pytest

import pip_audit._format as format


@pytest.mark.parametrize("output_desc", [True, False])
def test_columns_not_manifest(output_desc):
    fmt = format.ColumnsFormat(output_desc)
    assert not fmt.is_manifest


def test_columns(vuln_data):
    columns_format = format.ColumnsFormat(True)
    expected_columns = """Name Version ID     Fix Versions Description
---- ------- ------ ------------ ------------------------
foo  1.0     VULN-0 1.1,1.4      The first vulnerability
foo  1.0     VULN-1 1.0          The second vulnerability
bar  0.1     VULN-2              The third vulnerability"""
    assert columns_format.format(vuln_data, list()) == expected_columns


def test_columns_no_desc(vuln_data):
    columns_format = format.ColumnsFormat(False)
    expected_columns = """Name Version ID     Fix Versions
---- ------- ------ ------------
foo  1.0     VULN-0 1.1,1.4
foo  1.0     VULN-1 1.0
bar  0.1     VULN-2"""
    assert columns_format.format(vuln_data, list()) == expected_columns


def test_columns_skipped_dep(vuln_data_skipped_dep):
    columns_format = format.ColumnsFormat(False)
    expected_columns = """Name Version ID     Fix Versions
---- ------- ------ ------------
foo  1.0     VULN-0 1.1,1.4
Name Skip Reason
---- -----------
bar  skip-reason"""
    assert columns_format.format(vuln_data_skipped_dep, list()) == expected_columns


def test_columns_no_vuln_data(no_vuln_data):
    columns_format = format.ColumnsFormat(False)
    expected_columns = str()
    assert columns_format.format(no_vuln_data, list()) == expected_columns


def test_column_no_vuln_data_skipped_dep(no_vuln_data_skipped_dep):
    columns_format = format.ColumnsFormat(False)
    expected_columns = """Name Skip Reason
---- -----------
bar  skip-reason"""
    assert columns_format.format(no_vuln_data_skipped_dep, list()) == expected_columns


def test_columns_fix(vuln_data, fix_data):
    columns_format = format.ColumnsFormat(False)
    expected_columns = """Name Version ID     Fix Versions Applied Fix
---- ------- ------ ------------ --------------------------------------
foo  1.0     VULN-0 1.1,1.4      Successfully upgraded foo (1.0 => 1.8)
foo  1.0     VULN-1 1.0          Successfully upgraded foo (1.0 => 1.8)
bar  0.1     VULN-2              Successfully upgraded bar (0.1 => 0.3)"""
    assert columns_format.format(vuln_data, fix_data) == expected_columns


def test_columns_skipped_fix(vuln_data, skipped_fix_data):
    columns_format = format.ColumnsFormat(False)
    expected_columns = """Name Version ID     Fix Versions Applied Fix
---- ------- ------ ------------ --------------------------------------
foo  1.0     VULN-0 1.1,1.4      Successfully upgraded foo (1.0 => 1.8)
foo  1.0     VULN-1 1.0          Successfully upgraded foo (1.0 => 1.8)
bar  0.1     VULN-2              Failed to fix bar (0.1): skip-reason"""
    assert columns_format.format(vuln_data, skipped_fix_data) == expected_columns
