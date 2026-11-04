# Coverage-gap review — 2026-11-04

Reviewed source at b56bd349ae4ea1a15ee4085c8af01b20bc8c1fd2.

The coverage_gaps directory contains two test modules and an initializer.
Neither module has xfail decorators: previous parser-hang and reflection gaps
are positive regression assertions. Preserve those assertions and the 60-day
freshness gate.

- test_parser_gaps.py: six tests cover environment-variable concatenation,
  bounded parser completion, reflection nodes, suspicious verdicts, T1620,
  and assembly-load variants.
- test_correctness_feb2026.py: twelve tests cover version/IP distinction,
  address validation and provisional versus firm family risk contribution.

Follow-up retained: two malware-family tests condition assertions on a non-None
result and can pass without exercising attribution. Replace those probes with
deterministic fixtures in a dedicated correctness change; this review does not
claim that weakness is fixed. The SIGALRM parser tests are Linux-specific.

Evidence: GitHub run 41834681964 reported 819 passed, 3 skipped and one failed
freshness check. This is a source triage, not a new claim of complete engine,
HTTP, production or Windows validation. No test skips, thresholds or behavior
were relaxed. Updating the review date records this triage.
