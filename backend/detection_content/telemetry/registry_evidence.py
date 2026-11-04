"""D18 · registry evidence — observed registry telemetry, mapped honestly.

Raw Windows registry activity
  -> canonical registry entity
  -> per-field provenance
  -> deterministic detection
  -> evidence-backed rule firing
  -> cited investigation

Two sources genuinely OBSERVE the registry:

  * Sysmon EventID 12 (CreateKey/DeleteKey), 13 (SetValue) and 14
    (RenameKey) — `TargetObject`, `Details`, `EventType`, `NewName`;
  * Windows Security 4657 (a registry VALUE was modified) — `ObjectName`,
    `ObjectValueName`, `OperationType`, `NewValue`, `OldValue`,
    `NewValueType`.

The line this module will not cross: **a command line that mentions the
registry is not registry telemetry.** `reg add HKCU\\…\\Run /v x /d y` is an
observed PROCESS with an inferred intent. It produces no registry entity
here. Observed registry evidence and command-line inference stay separate
classes of evidence, so an investigation can always tell which one it is
looking at.

Every field is either OBSERVED (the source said it), DERIVED (computed from
what the source said, with the basis recorded) or NOT_OBSERVED (with the
reason). Nothing is filled in because it would look better populated.
"""
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from .models import RegistryEntity

#: This module only ever produces observed registry telemetry.
EVIDENCE_CLASS = "OBSERVED_REGISTRY_TELEMETRY"
#: What a command-line inference must be labelled as instead.
INFERENCE_CLASS = "COMMAND_LINE_INFERENCE_NOT_REGISTRY_TELEMETRY"

#: Sysmon `EventType` -> canonical action. Sysmon's own vocabulary.
SYSMON_ACTIONS = {
    "createkey": "create_key",
    "deletekey": "delete_key",
    "setvalue": "set_value",
    "deletevalue": "delete_value",
    "renamekey": "rename_key",
}

#: Windows Security 4657 `OperationType`. The %%-codes are Microsoft's.
WIN_4657_OPERATIONS = {
    "%%1904": "create_value",
    "%%1905": "set_value",
    "%%1906": "delete_value",
    "new registry value created": "create_value",
    "existing registry value modified": "set_value",
    "registry value deleted": "delete_value",
}

_HIVES = (
    "HKEY_LOCAL_MACHINE", "HKLM", "HKEY_CURRENT_USER", "HKCU",
    "HKEY_USERS", "HKU", "HKEY_CLASSES_ROOT", "HKCR",
    "HKEY_CURRENT_CONFIG", "HKCC",
    "\\REGISTRY\\MACHINE", "\\REGISTRY\\USER", "REGISTRY\\MACHINE",
    "REGISTRY\\USER",
)


def _f(value: Any, *, source: str, state: str = "OBSERVED",
       reason: Optional[str] = None, basis: Optional[str] = None
       ) -> Dict[str, Any]:
    """One field of registry evidence, with where it came from."""
    row: Dict[str, Any] = {"value": value if value not in ("", None) else None,
                           "state": state, "source": source}
    if row["value"] is None and state == "OBSERVED":
        row["state"] = "NOT_OBSERVED"
        row["reason"] = reason or f"{source} was empty in this record"
    if reason and row["state"] != "OBSERVED":
        row["reason"] = reason
    if basis:
        row["basis"] = basis
    return row


def _absent(source: str, reason: str) -> Dict[str, Any]:
    return {"value": None, "state": "NOT_OBSERVED", "source": source,
            "reason": reason}


def hive_of(key_path: str) -> Dict[str, Any]:
    """The hive a key path names, or NOT_OBSERVED — never a default hive."""
    upper = (key_path or "").upper()
    for hive in _HIVES:
        if upper.startswith(hive):
            return _f(hive, source="derived:leading hive of the key path",
                      state="DERIVED",
                      basis="the key path's own leading component")
    return _absent("derived:leading hive of the key path",
                   "this key path does not begin with a recognised hive; the "
                   "hive is not assumed")


def _split_value_name(target_object: str) -> Tuple[str, str]:
    """Sysmon 13 appends the value name to TargetObject. Split, don't guess."""
    if "\\" not in (target_object or ""):
        return target_object, ""
    key, _, value = target_object.rpartition("\\")
    return key, value


def from_sysmon(*, event_id: int, target_object: str, details: str = "",
                event_type: str = "", new_name: str = ""
                ) -> Tuple[RegistryEntity, Dict[str, Any]]:
    """Canonical registry evidence from a Sysmon 12/13/14 record."""
    declared_action = SYSMON_ACTIONS.get(str(event_type or "").strip().lower())
    if declared_action:
        action = _f(declared_action, source="sysmon:EventData.EventType")
    elif event_id == 13:
        action = _f("set_value", source="sysmon:EventID=13",
                    state="DERIVED",
                    basis="Sysmon EventID 13 IS RegistryEvent (Value Set) "
                          "by schema")
    elif event_id == 14:
        action = _f("rename_key", source="sysmon:EventID=14",
                    state="DERIVED",
                    basis="Sysmon EventID 14 IS RegistryEvent (Key and "
                          "Value Rename) by schema")
    else:
        action = _absent(
            "sysmon:EventData.EventType",
            "Sysmon EventID 12 covers BOTH CreateKey and DeleteKey and this "
            "record carried no EventType, so the operation is unknown — it "
            "is not assumed to be a create")

    value_operation = str(action["value"] or "").endswith("value")
    if value_operation and "\\" in (target_object or ""):
        key_path, value_name = _split_value_name(target_object)
        key_field = _f(key_path, source="sysmon:EventData.TargetObject",
                       state="DERIVED",
                       basis="TargetObject with the trailing value name "
                             "removed (Sysmon appends the value name for "
                             "value operations)")
        value_field = _f(value_name,
                         source="sysmon:EventData.TargetObject",
                         state="DERIVED",
                         basis="the trailing component of TargetObject")
    else:
        key_path, value_name = target_object, ""
        key_field = _f(target_object, source="sysmon:EventData.TargetObject")
        value_field = _absent(
            "sysmon:EventData.TargetObject",
            "this is a key-level operation; Sysmon names no registry value "
            "for it")

    data_field = (_f(details, source="sysmon:EventData.Details")
                  if event_id == 13 else
                  _absent("sysmon:EventData.Details",
                          "Sysmon emits Details only for value operations"))
    type_field = _absent(
        "sysmon:EventData",
        "Sysmon carries no separate registry value TYPE; the Details string "
        "is preserved verbatim rather than being parsed into a type")
    new_key_field = (_f(new_name, source="sysmon:EventData.NewName")
                     if new_name else
                     _absent("sysmon:EventData.NewName",
                             "this record is not a rename"))

    entity = RegistryEntity(
        hive=str(hive_of(key_path)["value"] or ""),
        key_path=key_path or "",
        value_name=value_field["value"] or "",
        value_data=str(data_field["value"] or ""),
        value_type="",
        action=str(action["value"] or ""),
        target_object=target_object or "",
        new_key_path=str(new_key_field["value"] or ""),
    )
    mapping = {
        "evidence_class": EVIDENCE_CLASS,
        "observed_by": f"sysmon:EventID={event_id}",
        "fields": {
            "hive": hive_of(key_path),
            "key_path": key_field,
            "value_name": value_field,
            "value_data": data_field,
            "value_type": type_field,
            "action": action,
            "target_object": _f(target_object,
                                source="sysmon:EventData.TargetObject"),
            "new_key_path": new_key_field,
        },
    }
    return entity, mapping


def from_windows_4657(data: Dict[str, Any]
                      ) -> Tuple[RegistryEntity, Dict[str, Any]]:
    """Canonical registry evidence from a Windows Security 4657 record."""
    def _d(*keys: str) -> str:
        for k in keys:
            v = data.get(k)
            if v not in (None, ""):
                return str(v)
        return ""

    key_path = _d("ObjectName")
    value_name = _d("ObjectValueName")
    op_raw = _d("OperationType")
    mapped = WIN_4657_OPERATIONS.get(op_raw.strip().lower())
    if mapped:
        action = _f(mapped, source="windows:EventData.OperationType",
                    basis=f"OperationType {op_raw!r}")
    else:
        action = _absent(
            "windows:EventData.OperationType",
            f"OperationType {op_raw!r} is not a documented 4657 operation, "
            "so the operation is recorded as unknown rather than guessed"
            if op_raw else
            "this 4657 record carried no OperationType")

    new_value = _d("NewValue")
    old_value = _d("OldValue")
    entity = RegistryEntity(
        hive=str(hive_of(key_path)["value"] or ""),
        key_path=key_path,
        value_name=value_name,
        value_data=new_value,
        value_type=_d("NewValueType"),
        action=str(action["value"] or ""),
        target_object=(f"{key_path}\\{value_name}"
                       if key_path and value_name else key_path),
    )
    mapping = {
        "evidence_class": EVIDENCE_CLASS,
        "observed_by": "windows:EventID=4657",
        "fields": {
            "hive": hive_of(key_path),
            "key_path": _f(key_path, source="windows:EventData.ObjectName"),
            "value_name": _f(
                value_name, source="windows:EventData.ObjectValueName",
                reason="this 4657 record named no registry value"),
            "value_data": _f(
                new_value, source="windows:EventData.NewValue",
                reason="4657 carries NewValue only when value auditing "
                       "captured it"),
            "value_type": _f(_d("NewValueType"),
                             source="windows:EventData.NewValueType"),
            "action": action,
            "target_object": _f(
                entity.target_object,
                source="derived:ObjectName + ObjectValueName",
                state="DERIVED",
                basis="4657 names the key and the value separately"),
            "previous_value_data": _f(
                old_value, source="windows:EventData.OldValue",
                reason="4657 carries OldValue only when value auditing "
                       "captured it"),
            "operation_type_raw": _f(
                op_raw, source="windows:EventData.OperationType"),
        },
    }
    return entity, mapping


def associations(*, device: str, device_source: str,
                 process_path: str = "", process_source: str = "",
                 process_id: Any = None,
                 username: str = "", identity_source: str = ""
                 ) -> Dict[str, Any]:
    """Who and what the SAME record associates with this registry activity.

    Association is only claimed when the record itself carried it. An absent
    actor is absent — never "SYSTEM", never the last process seen.
    """
    return {
        "device": (_f(device, source=device_source) if device
                   else _absent(device_source,
                                "this record named no computer")),
        "process": (_f(process_path, source=process_source) if process_path
                    else _absent(process_source,
                                 "this record named no acting process, so no "
                                 "process is associated with the registry "
                                 "activity")),
        "process_id": (_f(process_id, source=process_source)
                       if process_id not in (None, "")
                       else _absent(process_source,
                                    "this record named no acting process id")),
        "identity": (_f(username, source=identity_source) if username
                     else _absent(identity_source,
                                  "this record named no user, so the actor "
                                  "identity is unknown — not SYSTEM")),
    }
