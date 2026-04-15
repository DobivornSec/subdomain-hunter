from subhunter import SubdomainHunter, validate_domain
import aiohttp
import dns.resolver
import json
import asyncio


def test_validate_domain_accepts_valid_values():
    assert validate_domain("example.com")
    assert validate_domain("api.example.com")
    assert validate_domain("sub-1.example-domain.com")


def test_validate_domain_rejects_invalid_values():
    assert not validate_domain("localhost")
    assert not validate_domain("-bad.example.com")
    assert not validate_domain("bad_domain.example.com")


def test_generate_permutations_contains_expected_patterns():
    hunter = SubdomainHunter(domain="example.com", wordlist=[])
    perms = set(hunter.generate_permutations("api"))

    assert "dev-api" in perms
    assert "dev.api" in perms
    assert "api-dev" in perms
    assert "api1" in perms


def test_insecure_defaults_to_false():
    hunter = SubdomainHunter(domain="example.com", wordlist=[])
    assert hunter.insecure is False


def test_dns_retry_policy_only_retries_temporary_errors():
    hunter = SubdomainHunter(domain="example.com", wordlist=[])
    assert hunter.is_retryable_dns_error(dns.resolver.Timeout())
    assert not hunter.is_retryable_dns_error(dns.resolver.NXDOMAIN())


def test_http_retry_policy_only_retries_temporary_errors():
    hunter = SubdomainHunter(domain="example.com", wordlist=[])
    assert hunter.is_retryable_http_error(aiohttp.ClientConnectionError())
    assert not hunter.is_retryable_http_error(ValueError("bad url"))


def test_wildcard_result_detection_matches_intersection():
    hunter = SubdomainHunter(domain="example.com", wordlist=[])
    hunter.wildcard_dns_values = {"1.1.1.1", "wild.example.com"}

    assert hunter.is_wildcard_result({"ips": ["1.1.1.1"]})
    assert not hunter.is_wildcard_result({"ips": ["8.8.8.8"]})


def test_priority_score_prefers_sensitive_and_live_hosts():
    hunter = SubdomainHunter(domain="example.com", wordlist=[])
    high = hunter.calculate_priority_score(
        {
            "subdomain": "admin.example.com",
            "http": {"status": 200},
        }
    )
    low = hunter.calculate_priority_score(
        {
            "subdomain": "cdn.example.com",
            "http": {"status": 404},
        }
    )

    assert high > low
    assert 0 <= high <= 100


def test_calculate_stats_aggregates_http_summary():
    hunter = SubdomainHunter(domain="example.com", wordlist=[])
    hunter.found = [
        {
            "subdomain": "admin.example.com",
            "http": {"status": 200, "response_time_ms": 100.0},
        },
        {
            "subdomain": "api.example.com",
            "http": {"status": 404, "response_time_ms": 300.0},
        },
        {"subdomain": "mail.example.com"},
    ]
    stats = hunter.calculate_stats()

    assert stats["http_count"] == 2
    assert stats["dns_only_count"] == 1
    assert stats["status_distribution"] == {"200": 1, "404": 1}
    assert stats["avg_response_time_ms"] == 200.0


def test_load_priority_policy_overrides_defaults(tmp_path):
    policy_file = tmp_path / "priority_policy.json"
    policy_file.write_text(json.dumps({"high_signal_bonus": 5, "status_bonus_2xx": 50}), encoding="utf-8")

    hunter = SubdomainHunter(domain="example.com", wordlist=[], priority_policy=str(policy_file))
    score = hunter.calculate_priority_score({"subdomain": "admin.example.com", "http": {"status": 200}})
    assert score == 65


def test_apply_result_filters_supports_min_priority_and_top():
    hunter = SubdomainHunter(domain="example.com", wordlist=[], min_priority=50, top=2)
    results = [
        {"subdomain": "a.example.com", "priority_score": 90},
        {"subdomain": "b.example.com", "priority_score": 70},
        {"subdomain": "c.example.com", "priority_score": 55},
        {"subdomain": "d.example.com", "priority_score": 40},
    ]
    filtered = hunter.apply_result_filters(results)

    assert [item["subdomain"] for item in filtered] == ["a.example.com", "b.example.com"]


def test_profile_policy_changes_score_behavior():
    default_hunter = SubdomainHunter(domain="example.com", wordlist=[], profile="default")
    red_hunter = SubdomainHunter(domain="example.com", wordlist=[], profile="redteam")

    default_score = default_hunter.calculate_priority_score({"subdomain": "admin.example.com", "http": {"status": 401}})
    red_score = red_hunter.calculate_priority_score({"subdomain": "admin.example.com", "http": {"status": 401}})
    assert red_score > default_score


def test_policy_validation_ignores_invalid_types(tmp_path):
    policy_file = tmp_path / "bad_policy.json"
    policy_file.write_text(json.dumps({"high_signal_bonus": "oops", "status_bonus_2xx": 55}), encoding="utf-8")

    hunter = SubdomainHunter(domain="example.com", wordlist=[], priority_policy=str(policy_file))
    assert hunter.priority_policy["high_signal_bonus"] == 35
    assert hunter.priority_policy["status_bonus_2xx"] == 55


def test_score_breakdown_contains_reasons():
    hunter = SubdomainHunter(domain="example.com", wordlist=[])
    score, breakdown = hunter.calculate_priority_score_and_breakdown(
        {"subdomain": "admin.example.com", "http": {"status": 200}}
    )

    assert score > 0
    reasons = [item["reason"] for item in breakdown]
    assert "base_score" in reasons
    assert "high_signal_tokens" in reasons
    assert "status_2xx" in reasons


def test_wildcard_cname_filtering_works():
    hunter = SubdomainHunter(domain="example.com", wordlist=[])
    hunter.wildcard_cname_values = {"wild.edge.example.net"}
    assert hunter.is_wildcard_result({"ips": [], "cnames": ["wild.edge.example.net"]})


def test_verify_dns_stability_accepts_consistent_answers():
    hunter = SubdomainHunter(domain="example.com", wordlist=[], verify_rounds=2)

    class FakeAnswer:
        def __init__(self, value):
            self.value = value

        def __str__(self):
            return self.value

    def fake_resolve(_, record_type):
        if record_type in ("A", "AAAA"):
            return [FakeAnswer("1.1.1.1")]
        return []

    hunter.resolver.resolve = fake_resolve
    initial = {"subdomain": "api.example.com", "ips": ["1.1.1.1"], "cnames": []}
    assert asyncio.run(hunter.verify_dns_stability("api", initial))


def test_mode_strict_applies_more_defensive_defaults():
    hunter = SubdomainHunter(
        domain="example.com",
        wordlist=[],
        threads=100,
        retries=1,
        verify_rounds=1,
        min_priority=10,
        mode="strict",
    )
    assert hunter.threads == 40
    assert hunter.retries >= 3
    assert hunter.verify_rounds >= 3
    assert hunter.min_priority >= 50


def test_mode_aggressive_prefers_speed_defaults():
    hunter = SubdomainHunter(
        domain="example.com",
        wordlist=[],
        threads=20,
        retries=0,
        verify_rounds=3,
        mode="aggressive",
    )
    assert hunter.threads >= 80
    assert hunter.retries >= 1
    assert hunter.verify_rounds <= 2


def test_mode_adaptive_tightens_when_wildcard_detected():
    hunter = SubdomainHunter(
        domain="example.com",
        wordlist=[],
        threads=120,
        retries=1,
        verify_rounds=1,
        min_priority=0,
        mode="adaptive",
    )
    hunter.wildcard_dns_values = {"1.1.1.1"}
    hunter.adapt_runtime_settings(total_targets=300)

    assert hunter.verify_rounds >= 3
    assert hunter.min_priority >= 45
    assert hunter.threads <= 40
    assert hunter.retries >= 3


def test_adaptive_feedback_tightens_on_low_signal():
    hunter = SubdomainHunter(domain="example.com", wordlist=[], mode="adaptive", threads=120)
    hunter.apply_feedback_from_metrics(resolved_rate=0.03, http_hit_rate=0.01, wildcard_filter_rate=0.5)

    assert hunter.verify_rounds >= 3
    assert hunter.min_priority >= 55
    assert hunter.threads <= 45


def test_adaptive_feedback_scales_on_high_signal():
    hunter = SubdomainHunter(domain="example.com", wordlist=[], mode="adaptive", threads=40)
    hunter.apply_feedback_from_metrics(resolved_rate=0.35, http_hit_rate=0.2, wildcard_filter_rate=0.02)

    assert hunter.threads >= 110
    assert hunter.verify_rounds >= 2


def test_adaptive_decision_log_is_recorded_when_settings_change():
    hunter = SubdomainHunter(domain="example.com", wordlist=[], mode="adaptive", threads=40)
    hunter.apply_feedback_from_metrics(resolved_rate=0.35, http_hit_rate=0.2, wildcard_filter_rate=0.02)

    assert len(hunter.adaptive_decisions) >= 1
    decision = hunter.adaptive_decisions[-1]
    assert decision["trigger"] == "runtime_feedback"
    assert "before" in decision and "after" in decision


def test_adaptive_decision_summary_reports_shifts():
    hunter = SubdomainHunter(domain="example.com", wordlist=[], mode="adaptive")
    hunter.adaptive_decisions = [
        {
            "before": {"threads": 120, "retries": 2, "verify_rounds": 2, "min_priority": 20},
            "after": {"threads": 40, "retries": 3, "verify_rounds": 3, "min_priority": 55},
        },
        {
            "before": {"threads": 40, "retries": 3, "verify_rounds": 3, "min_priority": 55},
            "after": {"threads": 120, "retries": 3, "verify_rounds": 2, "min_priority": 45},
        },
    ]

    summary = hunter.summarize_adaptive_decisions()
    assert summary["total_decisions"] == 2
    assert summary["strict_shifts"] >= 1
    assert summary["throughput_shifts"] >= 1
    assert "avg_delta" in summary
