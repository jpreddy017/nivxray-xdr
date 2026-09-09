/*
 * v2 workspace theme — glassy navy-black + emerald green corporate palette.
 * Shared by every workspace surface (Device Trajectory, IRG, canvases).
 * Keep this file dependency-free so both React pages AND the Konva canvas
 * modules can import it without circular-dependency issues.
 */
export const T = {
  // Page background — deep navy black
  bg:       "#05080F",
  // Card surface — glassy navy
  paper:    "#0E1626",
  // Nested surface (chips, dropdowns, hover targets)
  paper2:   "#141F35",
  // Text ramp — near-white with subtle blue on dark bg
  ink:      "#E6EDF7",
  inkDim:   "#B4C0D2",
  inkMute:  "#7E8DA5",
  inkFaint: "#4C5A75",
  // Borders
  line:     "#1E2A44",
  lineStr:  "#2C3B5C",
  gray:     "#5A6B85",
  // Malicious
  red:      "#F87171",
  redT:     "#3A1E24",
  // Emerald green replaces amber ("amber" key preserved for legacy code paths;
  // it now renders in green so every previously-yellow bar / band / dot renders
  // in the corporate emerald palette).
  amber:    "#10B981",
  amberT:   "#0E3B2C",
  amberBg:  "rgba(16, 185, 129, 0.10)",
  green:    "#34D399",
  greenT:   "#0E3B2C",
  // Selection accent
  blue:     "#5EB0FF",
  blueT:    "#182E4A",
  // Faint band background
  band:     "#101B2E",
  // Glassy card gradient (used by outer cards)
  cardGradient:
    "linear-gradient(140deg, rgba(20,32,55,0.90) 0%, rgba(14,22,38,0.94) 60%, rgba(11,18,32,0.96) 100%)",
};
