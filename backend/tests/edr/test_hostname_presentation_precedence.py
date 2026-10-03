"""The trajectory must NAME an endpoint by its authoritative enrolment hostname.

Production defect this closes: the observation plane substitutes the platform
`endpoint_id` for a missing sensor hostname, so the trajectory presented
`ep_a67be48d5b4e01d4d9e8` as the machine name while the enrolment registry
already held `KUSHU`. The correction is READ-TIME presentation precedence only:
identity resolution, aliases, `device_iid`, tenancy and evidence addressing are
unchanged, and an absent name stays absent rather than being fabricated.
"""
from routers.edr import (_computer_header, _display_hostname,
                         _identity_with_display_hostname)

ENDPOINT_ID = "ep_a67be48d5b4e01d4d9e8"
DEVICE_IID = "dev_d21e1278f914"
TENANT = "ten_e759b7288598bd882e3dcac49d"

#: What the resolver returns today: hostname == the substituted endpoint_id.
DESCRIPTOR = {"resolved": True, "resolved_via": "endpoint_id",
              "device_iid": DEVICE_IID, "hostname": ENDPOINT_ID,
              "endpoint_id": ENDPOINT_ID, "tenant_id": TENANT,
              "addressed_by": [DEVICE_IID, ENDPOINT_ID]}

#: The authoritative enrolment record.
ENDPOINT_DOC = {"endpoint_id": ENDPOINT_ID, "hostname": "KUSHU",
                "tenant_id": TENANT, "enrollment_state": "ENROLLED",
                "sensor_state": "REPORTING", "platform": "Windows",
                "sensor_version": "0.3.0-windows"}

OUT = {"time_range": {"observed_start": "2026-10-01T00:00:00Z",
                      "observed_end": "2026-10-03T00:00:00Z"},
       "lane_axis": {"total_lanes": 3}, "observations_all_time": 40175}


def test_enrolment_hostname_wins_over_substituted_observation_name():
    name, basis = _display_hostname(DESCRIPTOR, ENDPOINT_DOC)
    assert name == "KUSHU"
    assert basis == "ENROLMENT_REPORTED"


def test_identity_shows_kushu_and_preserves_every_resolution_fact():
    ident = _identity_with_display_hostname(DESCRIPTOR, ENDPOINT_DOC)
    assert ident["hostname"] == "KUSHU"
    assert ident["hostname_basis"] == "ENROLMENT_REPORTED"
    # the substituted name is DISCLOSED, never silently dropped
    assert ident["observed_hostname"] == ENDPOINT_ID
    # endpoint identity, device identity, tenancy and addressing are untouched
    assert ident["endpoint_id"] == ENDPOINT_ID
    assert ident["device_iid"] == DEVICE_IID
    assert ident["tenant_id"] == TENANT
    assert ident["addressed_by"] == [DEVICE_IID, ENDPOINT_ID]
    assert ident["resolved_via"] == "endpoint_id"
    assert ident["resolved"] is True


def test_computer_header_shows_kushu_not_the_endpoint_id():
    comp = _computer_header(DESCRIPTOR, ENDPOINT_DOC, OUT)
    assert comp["hostname"] == "KUSHU"
    assert comp["hostname_basis"] == "ENROLMENT_REPORTED"
    assert comp["endpoint_id"] == ENDPOINT_ID
    assert comp["device_iid"] == DEVICE_IID
    assert comp["tenant"] == TENANT


def test_observation_hostname_is_used_when_enrolment_states_none():
    doc = {k: v for k, v in ENDPOINT_DOC.items() if k != "hostname"}
    ident = {**DESCRIPTOR, "hostname": "real-sensor-host"}
    name, basis = _display_hostname(ident, doc)
    assert (name, basis) == ("real-sensor-host", "OBSERVATION_DERIVED")


def test_absent_hostname_stays_absent_and_is_never_fabricated():
    doc = {k: v for k, v in ENDPOINT_DOC.items() if k != "hostname"}
    ident = {**DESCRIPTOR, "hostname": None}
    name, basis = _display_hostname(ident, doc)
    assert name is None
    assert basis == "HOSTNAME_NOT_COLLECTED"
    comp = _computer_header(ident, doc, OUT)
    assert comp["hostname"] is None
    assert comp["hostname_basis"] == "HOSTNAME_NOT_COLLECTED"
    # no username, no endpoint_id, no device_iid is promoted into the name
    assert comp["hostname"] not in (ENDPOINT_ID, DEVICE_IID)


def test_blank_enrolment_hostname_is_not_treated_as_a_name():
    name, basis = _display_hostname(DESCRIPTOR, {**ENDPOINT_DOC,
                                                 "hostname": "   "})
    assert (name, basis) == (ENDPOINT_ID, "OBSERVATION_DERIVED")
