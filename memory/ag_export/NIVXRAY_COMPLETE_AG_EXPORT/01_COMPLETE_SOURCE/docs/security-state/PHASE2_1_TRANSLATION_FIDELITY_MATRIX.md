# NivXRay XDR — Phase 2.1 Translation Fidelity & Adversarial Corpus Matrix

**Authority**: NivXRay Security Architecture Review Board  
**Document ID**: NIR-TX-FIDELITY-2.1  
**Date**: September 4, 2026  
**Status**: APPROVED  

---

## 1. Architectural Principles of Translation

The NivXRay Translation Manager converts heterogeneous external detection queries (Sigma, SPL, KQL, EQL) into the internal Canonical IR (NIR AST). The translation engine enforces three strict architectural invariants:
1. **Deterministic Equivalence**: Identical source query text produces identical NIR AST nodes and required field manifests.
2. **No Silent Weakening**: Whenever a source query contains constructs that cannot be faithfully evaluated by the target engine (e.g. multi-event aggregations, stateful sequence terminators, unsupported functions), the translator **NEVER** drops the construct or weakens the predicate. It must explicitly flag the construct as `UnsupportedConstruct(fatal=True)` and set fidelity to `UNSUPPORTED` or `PARTIAL`.
3. **Promotion Gating**: Canonical IR objects tagged with `UNSUPPORTED` or `APPROXIMATE` fidelity fail the `is_promotable()` check and are prohibited from being bound to live execution engines.

---

## 2. 22 Adversarial Syntax Cases Matrix

| Case ID | Format | Syntax Scenario / Construct Tested | Target NIR AST Mapping | Fidelity Rating | Silent Weakening Check | Promotable? | Test File |
| :---: | :---: | :--- | :--- | :---: | :---: | :---: | :--- |
| **TX-01** | Sigma | Deeply nested boolean logic (50 chained selections) | `BooleanLogicNode(AND, ...)` | `EXACT` | Full tree preserved; zero dropped clauses | Yes | `test_phase2_1_translation_adversarial.py` |
| **TX-02** | Sigma | Regex modifier (`CommandLine\|re: '...'`) | `FieldCompareNode(REGEX, ...)` | `STRONG` | Pattern preserved with case sensitivity flag | Yes | `test_phase2_1_translation_adversarial.py` |
| **TX-03** | Sigma | Case-sensitive modifier (`Image\|cased: '...'`) | `FieldCompareNode(EQUALS, cased=True)` | `EXACT` | Strict case enforcement | Yes | `test_phase2_1_translation_adversarial.py` |
| **TX-04** | Sigma | List selection with `all` modifier (`CommandLine\|contains\|all`) | `BooleanLogicNode(AND, [FieldCompareNode...])` | `EXACT` | Conjunction enforced | Yes | `test_phase2_1_translation_adversarial.py` |
| **TX-05** | Sigma | Aggregation condition (`count() by host > 5`) | `UnsupportedConstruct(fatal=True)` | `UNSUPPORTED` | **Fails closed**; barred from single-event execution | No | `test_phase2_1_translation_adversarial.py` |
| **TX-06** | Sigma | Malformed YAML / Unclosed brackets | `TranslationResult(success=False)` | `UNSUPPORTED` | Deterministic parse failure captured | No | `test_phase2_1_translation_adversarial.py` |
| **TX-07** | Sigma | Missing condition block | `TranslationResult(success=False)` | `UNSUPPORTED` | Fatal syntax error preserved | No | `test_phase2_1_translation_adversarial.py` |
| **TX-08** | SPL | Subsearch construct (`[ search sourcetype=... ]`) | `UnsupportedConstruct(fatal=True)` | `UNSUPPORTED` | **Fails closed**; subsearch not stripped | No | `test_phase2_1_translation_adversarial.py` |
| **TX-09** | SPL | `stats count by host \| where count > 5` | `TimeWindowNode(child=AggregationRefNode)` | `STRONG` | Converted to correlation; single-event blocked | Yes (Corr) | `test_phase2_1_translation_adversarial.py` |
| **TX-10** | SPL | Table pipe (`\| table host, user, cmd`) | Projection metadata | `EXACT` | Preserves projection without altering predicates | Yes | `test_phase2_1_translation_adversarial.py` |
| **TX-11** | SPL | Regex extract (`\| rex field=CommandLine "..."`) | `UnsupportedConstruct(fatal=True)` | `UNSUPPORTED` | **Fails closed**; runtime extraction not simulated | No | `test_phase2_1_translation_adversarial.py` |
| **TX-12** | SPL | Transaction grouping (`\| transaction host maxspan=5m`) | `TimeWindowNode(child=SequenceRefNode)` | `STRONG` | Stateful window preserved | Yes (Corr) | `test_phase2_1_translation_adversarial.py` |
| **TX-13** | KQL | Multiple piped where clauses (`\| where ... \| where ...`) | `BooleanLogicNode(AND, [...])` | `EXACT` | Conjunction preserved across pipes | Yes | `test_phase2_1_translation_adversarial.py` |
| **TX-14** | KQL | Case-insensitive equals (`=~`) and in (`in~`) | `FieldCompareNode(EQUALS/IN_SET, cased=False)` | `EXACT` | Case insensitivity explicitly asserted | Yes | `test_phase2_1_translation_adversarial.py` |
| **TX-15** | KQL | Regex match (`matches regex @"..."`) | `FieldCompareNode(REGEX, ...)` | `STRONG` | Regex pattern extracted cleanly | Yes | `test_phase2_1_translation_adversarial.py` |
| **TX-16** | KQL | Multi-value `in` set (`ProcessCommandLine in ("-enc", "/e")`) | `FieldCompareNode(IN_SET, [...])` | `EXACT` | Discrete set comparison | Yes | `test_phase2_1_translation_adversarial.py` |
| **TX-17** | KQL | Unsupported join (`\| join kind=inner (DeviceNetworkEvents)`) | `UnsupportedConstruct(fatal=True)` | `UNSUPPORTED` | **Fails closed**; stateful join rejected | No | `test_phase2_1_translation_adversarial.py` |
| **TX-18** | KQL | `summarize count() by DeviceName \| where count_ > 10` | `TimeWindowNode(child=AggregationRefNode)` | `STRONG` | Correlation routed; threshold verified | Yes (Corr) | `test_phase2_1_translation_adversarial.py` |
| **TX-19** | EQL | Sequence with maxspan (`sequence with maxspan=5m [...] [...]`) | `TimeWindowNode(child=SequenceRefNode)` | `STRONG` | Stages and span extracted without loss | Yes (Corr) | `test_phase2_1_translation_adversarial.py` |
| **TX-20** | EQL | Sequence with `until` clause | `UnsupportedConstruct(fatal=True)` | `UNSUPPORTED` | **Fails closed**; until terminator not dropped | No | `test_phase2_1_translation_adversarial.py` |
| **TX-21** | EQL | Wildcards in `==` comparison (`command_line == "* /priv"`) | `FieldCompareNode(ENDSWITH, " /priv")` | `STRONG` | Converted to suffix match without regex overhead | Yes | `test_phase2_1_translation_adversarial.py` |
| **TX-22** | EQL | Malformed missing closing bracket (`[process where ...`) | `TranslationResult(success=False)` | `UNSUPPORTED` | Fatal parse error captured | No | `test_phase2_1_translation_adversarial.py` |

---

## 3. Semantic Equivalence Proofs

Semantic equivalence was physically proven by evaluating translated NIR AST against positive match events and negative control events:

### 3.1 Sigma Semantic Proof (`test_sigma_semantic_equivalence_execution`)
- **Query**: Encoded PowerShell execution with filter on `NT AUTHORITY\SYSTEM`.
- **Positive Event 1** (`powershell.exe -enc ...` by normal user): Matches `True` ✅
- **Positive Event 2** (`powershell.exe -encodedcommand ...` by normal user): Matches `True` ✅
- **Negative Event 1** (`powershell.exe` without encoded flag): Matches `False` ✅
- **Negative Event 2** (`powershell.exe -enc ...` by `NT AUTHORITY\SYSTEM`): Filter triggers, matches `False` ✅
- **Negative Event 3** (`cmd.exe /c echo -enc`): Process mismatch, matches `False` ✅

### 3.2 SPL Semantic Proof (`test_spl_semantic_equivalence_execution`)
- **Query**: `index=windows sourcetype=WinEventLog EventCode=4688 Image="*\\certutil.exe" (CommandLine="*urlcache*" OR CommandLine="*-split*")`
- **Positive Event** (`certutil.exe -urlcache -split ...`): Matches `True` ✅
- **Negative Event 1** (`certutil.exe -dump ...`): Missing download flag, matches `False` ✅
- **Negative Event 2** (`curl.exe -urlcache ...`): Non-certutil process, matches `False` ✅

### 3.3 KQL Semantic Proof (`test_kql_semantic_equivalence_execution`)
- **Query**: `DeviceProcessEvents | where FileName =~ "mshta.exe" and (ProcessCommandLine has "http" or ProcessCommandLine has "javascript:")`
- **Positive Event 1** (`MSHTA.EXE http://malicious.site/payload`): Matches `True` ✅
- **Positive Event 2** (`mshta.exe javascript:...`): Matches `True` ✅
- **Negative Event 1** (`mshta.exe local_file.hta`): No URL/JS, matches `False` ✅
- **Negative Event 2** (`cscript.exe http://...`): Wrong process name, matches `False` ✅

### 3.4 EQL Semantic Proof (`test_eql_semantic_equivalence_execution`)
- **Query**: `process where process.name == "whoami.exe" and process.command_line == "* /priv"`
- **Positive Event** (`C:\Windows\system32\whoami.exe /priv`): Suffix match succeeds, matches `True` ✅
- **Negative Event** (`C:\Windows\system32\whoami.exe /all`): Argument mismatch, matches `False` ✅

---

## 4. Conclusion

All 22 adversarial syntax scenarios satisfy strict translation and non-weakening criteria. The translation tier guarantees zero semantic dilution when mapping external content into NivXRay Canonical IR.
