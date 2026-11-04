import api from "@/lib/api";

export async function getFileObservations(params, signal) {
  const { data } = await api.get("/edr/endpoint-file-observations", { params, signal });
  return data;
}
