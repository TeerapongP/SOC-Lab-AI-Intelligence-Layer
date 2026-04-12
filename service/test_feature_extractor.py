import pytest
from enrich.models import EnrichedRecord
from feature_extractor.extractor import FeatureExtractor, _IOC_TYPE_MAP, _MITRE_PHASE_MAP


def _make_rec(**kwargs) -> EnrichedRecord:
    defaults = dict(
        src_ip="1.1.1.1", dst_ip="2.2.2.2",
        src_port=12345, dst_port=443,
        bytes_sent=5000.0, bytes_recv=2000.0,
        packets=50, session_duration=10.0,
        action="allow", app="ssl",
        rule="outbound", timestamp="2026-04-12T11:00:00",
    )
    defaults.update(kwargs)
    return EnrichedRecord(**defaults)


class TestFeatureExtractor:
    def setup_method(self):
        self.extractor = FeatureExtractor()

    def test_bytes_per_session(self):
        rec = _make_rec(bytes_sent=5000.0, bytes_recv=2000.0, session_duration=10.0)
        fv  = self.extractor.extract(rec)
        assert fv.bytes_per_session == pytest.approx(700.0)

    def test_login_velocity(self):
        rec = _make_rec(packets=100, session_duration=10.0)
        fv  = self.extractor.extract(rec)
        assert fv.login_velocity == pytest.approx(10.0)

    def test_failed_auth_ratio_deny(self):
        rec = _make_rec(action="deny")
        fv  = self.extractor.extract(rec)
        assert fv.failed_auth_ratio == 1.0

    def test_failed_auth_ratio_allow(self):
        rec = _make_rec(action="allow")
        fv  = self.extractor.extract(rec)
        assert fv.failed_auth_ratio == 0.0

    def test_ioc_type_encoding(self):
        rec = _make_rec(ioc_type="url")
        fv  = self.extractor.extract(rec)
        assert fv.ioc_type_enc == _IOC_TYPE_MAP["url"]

    def test_unknown_ioc_type_defaults_to_zero(self):
        rec = _make_rec(ioc_type="unknown-type")
        fv  = self.extractor.extract(rec)
        assert fv.ioc_type_enc == 0

    def test_mitre_phase_encoding(self):
        rec = _make_rec(mitre_phase="lateral-movement")
        fv  = self.extractor.extract(rec)
        assert fv.mitre_phase_enc == _MITRE_PHASE_MAP["lateral-movement"]

    def test_exfiltration_highest_severity(self):
        rec = _make_rec(mitre_phase="exfiltration")
        fv  = self.extractor.extract(rec)
        assert fv.mitre_phase_enc == 8

    def test_zero_session_duration_no_divzero(self):
        rec = _make_rec(session_duration=0.0, packets=10)
        fv  = self.extractor.extract(rec)
        assert fv.bytes_per_session > 0
        assert fv.login_velocity > 0

    def test_metadata_passthrough(self):
        rec = _make_rec(src_ip="3.3.3.3", dst_port=22, weak_label="attack")
        fv  = self.extractor.extract(rec)
        assert fv.src_ip == "3.3.3.3"
        assert fv.dst_port == 22
        assert fv.weak_label == "attack"

    def test_transform_without_scaler_returns_unscaled(self):
        rec = _make_rec()
        fv  = self.extractor.extract(rec)
        fv  = self.extractor.transform(fv)
        assert fv.scaled is not None
        assert len(fv.scaled) == 9

    def test_nine_features(self):
        rec = _make_rec()
        fv  = self.extractor.extract(rec)
        raw = self.extractor._to_array(fv)
        assert len(raw) == 9
