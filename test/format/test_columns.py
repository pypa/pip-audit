import pytest

import pip_audit._format as format
from pip_audit._format.columns import _osc8_link, _pypi_url, _vuln_id_url


# Shortcuts for building expected output with OSC8 links
def _P(name):
    return _osc8_link(name, _pypi_url(name))


def _V(vid):
    return _osc8_link(vid, _vuln_id_url(vid))


@pytest.mark.parametrize("output_desc, output_aliases", ([True, False], [True, False]))
def test_columns_not_manifest(output_desc, output_aliases):
    fmt = format.ColumnsFormat(output_desc, output_aliases)
    assert not fmt.is_manifest


def test_columns(vuln_data):
    columns_format = format.ColumnsFormat(True, True)
    expected_columns = f"""Name Version ID     Fix Versions Aliases        Description
---- ------- ------ ------------ -------------- ------------------------
{_P("foo")}  1.0     {_V("VULN-0")} 1.1,1.4      {_V("CVE-0000-00000")} The first vulnerability
{_P("foo")}  1.0     {_V("VULN-1")} 1.0          {_V("CVE-0000-00001")} The second vulnerability
{_P("bar")}  0.1     {_V("VULN-2")}              {_V("CVE-0000-00002")} The third vulnerability"""
    assert columns_format.format(vuln_data, []) == expected_columns


def test_columns_no_desc(vuln_data):
    columns_format = format.ColumnsFormat(False, True)
    expected_columns = f"""Name Version ID     Fix Versions Aliases
---- ------- ------ ------------ --------------
{_P("foo")}  1.0     {_V("VULN-0")} 1.1,1.4      {_V("CVE-0000-00000")}
{_P("foo")}  1.0     {_V("VULN-1")} 1.0          {_V("CVE-0000-00001")}
{_P("bar")}  0.1     {_V("VULN-2")}              {_V("CVE-0000-00002")}"""
    assert columns_format.format(vuln_data, []) == expected_columns


def test_columns_no_desc_no_aliases(vuln_data):
    columns_format = format.ColumnsFormat(False, False)
    expected_columns = f"""Name Version ID     Fix Versions
---- ------- ------ ------------
{_P("foo")}  1.0     {_V("VULN-0")} 1.1,1.4
{_P("foo")}  1.0     {_V("VULN-1")} 1.0
{_P("bar")}  0.1     {_V("VULN-2")}"""
    assert columns_format.format(vuln_data, []) == expected_columns


def test_columns_skipped_dep(vuln_data_skipped_dep):
    columns_format = format.ColumnsFormat(False, True)
    expected_columns = f"""Name Version ID     Fix Versions Aliases
---- ------- ------ ------------ --------------
{_P("foo")}  1.0     {_V("VULN-0")} 1.1,1.4      {_V("CVE-0000-00000")}

Name Skip Reason
---- -----------
bar  skip-reason"""
    assert columns_format.format(vuln_data_skipped_dep, []) == expected_columns


def test_columns_no_vuln_data(no_vuln_data):
    columns_format = format.ColumnsFormat(False, True)
    expected_columns = ""
    assert columns_format.format(no_vuln_data, []) == expected_columns


def test_column_no_vuln_data_skipped_dep(no_vuln_data_skipped_dep):
    columns_format = format.ColumnsFormat(False, True)
    expected_columns = """Name Skip Reason
---- -----------
bar  skip-reason"""
    assert columns_format.format(no_vuln_data_skipped_dep, []) == expected_columns


def test_columns_fix(vuln_data, fix_data):
    columns_format = format.ColumnsFormat(False, True)
    expected_columns = f"""Name Version ID     Fix Versions Applied Fix                            Aliases
---- ------- ------ ------------ -------------------------------------- --------------
{_P("foo")}  1.0     {_V("VULN-0")} 1.1,1.4      Successfully upgraded foo (1.0 => 1.8) {_V("CVE-0000-00000")}
{_P("foo")}  1.0     {_V("VULN-1")} 1.0          Successfully upgraded foo (1.0 => 1.8) {_V("CVE-0000-00001")}
{_P("bar")}  0.1     {_V("VULN-2")}              Successfully upgraded bar (0.1 => 0.3) {_V("CVE-0000-00002")}"""
    assert columns_format.format(vuln_data, fix_data) == expected_columns


def test_columns_skipped_fix(vuln_data, skipped_fix_data):
    columns_format = format.ColumnsFormat(False, True)
    expected_columns = f"""Name Version ID     Fix Versions Applied Fix                            Aliases
---- ------- ------ ------------ -------------------------------------- --------------
{_P("foo")}  1.0     {_V("VULN-0")} 1.1,1.4      Successfully upgraded foo (1.0 => 1.8) {_V("CVE-0000-00000")}
{_P("foo")}  1.0     {_V("VULN-1")} 1.0          Successfully upgraded foo (1.0 => 1.8) {_V("CVE-0000-00001")}
{_P("bar")}  0.1     {_V("VULN-2")}              Failed to fix bar (0.1): skip-reason   {_V("CVE-0000-00002")}"""
    assert columns_format.format(vuln_data, skipped_fix_data) == expected_columns
