// Small vector logo — asymmetric bracket + spark
export default function Logo({ size = 22 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg" style={{ display: "block" }}>
      <rect x="0.5" y="0.5" width="31" height="31" stroke="#2d3135" />
      <path d="M6 24 L6 8 L11 8 L20 20 L20 8 L26 8" stroke="#4aa890" strokeWidth="2" fill="none" strokeLinejoin="miter" />
      <circle cx="26" cy="24" r="2" fill="#e27e5d" />
    </svg>
  );
}
