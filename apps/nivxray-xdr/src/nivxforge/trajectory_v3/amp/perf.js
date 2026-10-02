// Client-side synthetic rows in the page's event shape, for the performance matrix only (?perf=N). Not evidence.
export function perfEvents(n, end = Date.now()) {
  const out = [], span = 86_400_000, procs = [];
  let seed = 7;
  const rnd = () => ((seed = (seed * 16807) % 2147483647) / 2147483647);
  for (let i = 0; i < n; i++) {
    const ms = end - span + Math.floor((i / n) * span), x = rnd();
    const parent = procs.length ? procs[Math.floor(rnd() * procs.length)] : null;
    const id = `obs_perf${String(i).padStart(8, "0")}#p${i}`;
    if (x < 0.25 || !parent) {
      const iid = `proc_perf_${i}`, image = `C:\\Apps\\app${Math.floor(rnd() * 400)}.exe`;
      procs.push({ iid, image }); if (procs.length > 300) procs.shift();
      out.push({ event_iid: id, observation_id: id.split("#")[0], timestamp_instant_ms: ms, event_type: "process_create", image, process_iid: iid,
        parent_process_iid: parent?.iid, parent_image: parent?.image, parent_process_guid: parent ? "g" : null, pid: String(1000 + i), command_line: x < 0.1 ? "app.exe -x" : null });
    } else if (x < 0.65) {
      out.push({ event_iid: id, observation_id: id.split("#")[0], timestamp_instant_ms: ms, event_type: "file_create", image: parent.image, process_iid: parent.iid,
        file: `C:\\Data\\f${Math.floor(rnd() * 3000)}.${["tmp", "js", "pdf", "zip", "docx"][i % 5]}` });
    } else {
      out.push({ event_iid: id, observation_id: id.split("#")[0], timestamp_instant_ms: ms, event_type: "network_connect", image: parent.image, process_iid: parent.iid,
        network: `10.0.${Math.floor(rnd() * 40)}.${Math.floor(rnd() * 250)}` });
    }
  }
  return out;
}
