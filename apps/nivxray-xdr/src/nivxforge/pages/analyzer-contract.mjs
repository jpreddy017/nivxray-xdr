export function analysisError(error) {
  const status = error?.response?.status;
  if (status === 401) return 'Your session expired. Sign in and retry.';
  if (status === 403) return 'This account cannot analyze commands for the selected customer.';
  if (status === 404) return 'The analyzer backend is not installed in this environment.';
  if (status === 429) return 'Too many requests. Wait before retrying.';
  if (status === 503) return 'The analyzer is busy or unavailable. Retry shortly.';
  const detail = error?.response?.data?.detail;
  if (typeof detail === 'string') return detail;
  if (Array.isArray(detail)) return detail.map(item => item.msg || 'Invalid input').join('; ');
  if (detail && typeof detail.message === 'string') return detail.message;
  return error?.message || 'Analysis failed.';
}

export function validateReport(data, tenant, inputHash) {
  if (data?.tenant_id !== tenant || data?.input_sha256 !== inputHash ||
      data?.report?.executed !== false || !Array.isArray(data?.report?.layers) ||
      !Array.isArray(data?.report?.indicators) || !data?.report?.explanation ||
      data?.report?.analyzer_version !== '2026.11.16.2') {
    throw new Error('The analysis response does not match this input, customer, or analyzer version. Retry after deployment completes.');
  }
  return data;
}

