from umat.operations.metrics import Metrics


def test_metrics_use_only_bounded_labels() -> None:
    registry = Metrics()
    registry.observe_request("GET", 201, 0.25)
    registry.observe_request("GET", 204, 0.75)
    output = registry.render()
    assert 'method="GET",status_class="2xx"} 2' in output
    assert "umat_http_request_duration_seconds_sum 1.0" in output
