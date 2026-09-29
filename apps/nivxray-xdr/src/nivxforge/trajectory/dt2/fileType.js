/**
 * Cisco's DISPLAYED FILE TYPES — the documented engineering reason a Cisco
 * trajectory never looks like a dump of every file an application touches.
 *
 * Cisco TAC doc 118711, "File Types That are Scanned by Cisco Secure
 * Endpoint on Public Cloud", verbatim:
 *
 *   "There are different levels of reporting between the Cisco Secure
 *    Endpoint, Event Console, and Device Trajectory. Although a file is
 *    scanned at the connector level, only certain files are queried against
 *    the Public Cloud. This narrowing of events is not to hide visibility,
 *    but to accent the more important indications of compromise and not
 *    weigh down the system with inconsequential files."
 *
 * Secure Endpoint User Guide p.401, verbatim:
 *
 *   "Device Trajectory displays the following file types:
 *      Executable files · Portable Document Format (PDF) files ·
 *      MS Cabinet files · MS Office files · Archive files ·
 *      Adobe Shockwave Flash · Plain text files · Rich text files ·
 *      Script files · Installer files"
 *
 * and p.406: "There are five event filter categories in Device Trajectory:
 * Activity, System, Disposition, Flags, File Type."
 *
 * Chrome's `001425.ldb` and WhatsApp's `009034.log` are in none of those
 * classes, which is why Cisco's own trajectory would not carry them as
 * rows. Classification is DOCUMENTED, not inferred.
 *
 * TWO HONEST DIFFERENCES FROM CISCO'S ENGINEERING, stated rather than
 * papered over:
 *
 *   1. WHERE it narrows. Cisco narrows at the cloud query, so the event
 *      never reaches the trajectory at all. NivXForge narrows at DISPLAY:
 *      the observation is kept, remains in the Activity pane and the API,
 *      and `Other` brings it back onto the axis. Less destructive, same
 *      analyst effect.
 *   2. HOW the class is decided. Cisco identifies the type from file
 *      content (its cloud-queried set is a list of type identities —
 *      MSEXE, MSOLE2, OOXML_WORD, POWERSHELL, SCRIPT, LNK, MBR, REGISTRY,
 *      SETUP_INFO, SWF, ZIP, PDF, HTML_APP …), not from the name. The
 *      NivXForge sensor sends no file-identification verdict, so the class
 *      here is derived from the OBSERVED PATH:
 *
 *      BASIS = PATH_EXTENSION_DERIVED_NOT_CONTENT_IDENTIFIED
 *
 *      An extension can lie. Nothing is claimed about content, and the
 *      filter states this.
 */
export const TYPES = [
  ["EXECUTABLE", "Executable files"],
  ["PDF", "PDF files"],
  ["CABINET", "MS Cabinet files"],
  ["OFFICE", "MS Office files"],
  ["ARCHIVE", "Archive files"],
  ["FLASH", "Adobe Shockwave Flash"],
  ["TEXT", "Plain text files"],
  ["RICHTEXT", "Rich text files"],
  ["SCRIPT", "Script files"],
  ["INSTALLER", "Installer files"],
];

export const OTHER = "OTHER";
export const OTHER_LABEL = "Other (outside Cisco's displayed set)";

/** Cisco's documented display set — the default selection. */
export const CISCO_DISPLAYED = TYPES.map(([k]) => k);

const EXT = {
  exe: "EXECUTABLE", dll: "EXECUTABLE", sys: "EXECUTABLE",
  scr: "EXECUTABLE", com: "EXECUTABLE", ocx: "EXECUTABLE",
  cpl: "EXECUTABLE", efi: "EXECUTABLE", drv: "EXECUTABLE",
  pdf: "PDF",
  cab: "CABINET",
  doc: "OFFICE", docx: "OFFICE", docm: "OFFICE", dot: "OFFICE",
  dotm: "OFFICE", xls: "OFFICE", xlsx: "OFFICE", xlsm: "OFFICE",
  ppt: "OFFICE", pptx: "OFFICE", pptm: "OFFICE", rtf: "RICHTEXT",
  zip: "ARCHIVE", rar: "ARCHIVE", "7z": "ARCHIVE", gz: "ARCHIVE",
  tar: "ARCHIVE", bz2: "ARCHIVE", xz: "ARCHIVE", iso: "ARCHIVE",
  swf: "FLASH",
  txt: "TEXT", ini: "TEXT", cfg: "TEXT", csv: "TEXT", xml: "TEXT",
  ps1: "SCRIPT", psm1: "SCRIPT", bat: "SCRIPT", cmd: "SCRIPT",
  vbs: "SCRIPT", vbe: "SCRIPT", js: "SCRIPT", jse: "SCRIPT",
  wsf: "SCRIPT", wsh: "SCRIPT", hta: "SCRIPT", py: "SCRIPT",
  sh: "SCRIPT", php: "SCRIPT", jar: "SCRIPT",
  msi: "INSTALLER", msp: "INSTALLER", msix: "INSTALLER",
  appx: "INSTALLER", mst: "INSTALLER", inf: "INSTALLER",
};

/** Why a class was assigned. Cisco identifies by content; we do not. */
export const CLASS_BASIS = "PATH_EXTENSION_DERIVED_NOT_CONTENT_IDENTIFIED";

/** The Cisco display class of an observed path, or `OTHER`. */
export function fileTypeOf(path) {
  if (!path) return OTHER;
  const name = String(path).split(/[\\/]/).pop() || "";
  const dot = name.lastIndexOf(".");
  if (dot <= 0 || dot === name.length - 1) return OTHER;
  return EXT[name.slice(dot + 1).toLowerCase()] || OTHER;
}

export const typeLabelOf = (key) => (
  key === OTHER ? OTHER_LABEL
    : (TYPES.find(([k]) => k === key) || [, key])[1]);
