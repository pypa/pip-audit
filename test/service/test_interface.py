def test_vulnerability_service(vuln_service, spec):
    service = vuln_service()
    spec = spec("1.0.1")

    assert len(service.query(spec)) == 1

    all_ = dict(service.query_all([spec]))
    assert len(all_) == 1
    assert len(all_[spec]) == 1


def test_vulnerability_service_no_results(vuln_service, spec):
    service = vuln_service()
    spec = spec("1.1.1")

    assert len(service.query(spec)) == 0
