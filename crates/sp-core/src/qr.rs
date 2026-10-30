//! QR encoding for on-screen display.
//!
//! The KeyOS platform renderer draws one pixel per module and then rounds the image corners with
//! a fixed 24 px radius, which on a ~50 px image cuts into the finder patterns. The app therefore
//! renders codes itself from this matrix: dark modules on white, a four-module quiet zone (the
//! minimum in ISO/IEC 18004), integer scaling, no masking.

use qrcode::{Color, EcLevel, QrCode};

/// Quiet zone width in modules.
pub const QUIET_ZONE: usize = 4;

/// Error-correction level used for every code the app shows.
pub const EC_LEVEL: EcLevel = EcLevel::M;

/// The payload does not fit in a QR code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QrTooLong;

/// A QR symbol as a square grid of modules (without quiet zone).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QrMatrix {
    width: usize,
    dark: Vec<bool>,
}

impl QrMatrix {
    /// Encodes `payload` byte-for-byte; nothing is added or changed.
    pub fn encode(payload: &str) -> Result<Self, QrTooLong> {
        let code = QrCode::with_error_correction_level(payload.as_bytes(), EC_LEVEL).map_err(|_| QrTooLong)?;
        let dark = code.to_colors().into_iter().map(|c| c == Color::Dark).collect();
        Ok(Self { width: code.width(), dark })
    }

    /// Modules per side, excluding the quiet zone.
    pub fn width(&self) -> usize { self.width }

    /// Modules per side, including the quiet zone on both sides.
    pub fn width_with_quiet_zone(&self) -> usize { self.width + 2 * QUIET_ZONE }

    /// Whether module `(x, y)` is dark. Coordinates include the quiet zone.
    pub fn is_dark(&self, x: usize, y: usize) -> bool {
        let (Some(x), Some(y)) = (x.checked_sub(QUIET_ZONE), y.checked_sub(QUIET_ZONE)) else { return false };
        x < self.width && y < self.width && self.dark[y * self.width + x]
    }

    /// Largest integer pixels-per-module so the whole code fits in `max_px`, at least 1.
    pub fn scale_for(&self, max_px: usize) -> usize { (max_px / self.width_with_quiet_zone()).max(1) }

    /// RGBA8 pixels, `scale` pixels per module, black on white. Returns `(side_px, pixels)`.
    pub fn to_rgba(&self, scale: usize) -> (usize, Vec<u8>) {
        let scale = scale.max(1);
        let side = self.width_with_quiet_zone() * scale;
        let mut pixels = vec![0xffu8; side * side * 4];
        for py in 0..side {
            for px in 0..side {
                if self.is_dark(px / scale, py / scale) {
                    let i = (py * side + px) * 4;
                    pixels[i..i + 3].fill(0x00);
                }
            }
        }
        (side, pixels)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quiet_zone_is_light_and_finder_corner_is_dark() {
        let m = QrMatrix::encode("sp1qexample").unwrap();
        let n = m.width_with_quiet_zone();
        for i in 0..n {
            for q in 0..QUIET_ZONE {
                assert!(!m.is_dark(i, q) && !m.is_dark(q, i) && !m.is_dark(i, n - 1 - q) && !m.is_dark(n - 1 - q, i));
            }
        }
        // Top-left module of the top-left finder pattern is always dark.
        assert!(m.is_dark(QUIET_ZONE, QUIET_ZONE));
        assert!(m.is_dark(QUIET_ZONE + m.width() - 1, QUIET_ZONE));
        assert!(m.is_dark(QUIET_ZONE, QUIET_ZONE + m.width() - 1));
    }

    #[test]
    fn rgba_scaling() {
        let m = QrMatrix::encode("abc").unwrap();
        let (side, px) = m.to_rgba(3);
        assert_eq!(side, m.width_with_quiet_zone() * 3);
        assert_eq!(px.len(), side * side * 4);
        let at = |x: usize, y: usize| px[(y * side + x) * 4];
        assert_eq!(at(0, 0), 0xff);
        assert_eq!(at(QUIET_ZONE * 3, QUIET_ZONE * 3), 0x00);
        assert!(px.chunks(4).all(|p| p[3] == 0xff), "fully opaque");
        assert_eq!(m.scale_for(10_000), 10_000 / m.width_with_quiet_zone());
        assert_eq!(m.scale_for(1), 1);
    }

    #[test]
    fn rejects_oversized_payload() {
        assert_eq!(QrMatrix::encode(&"a".repeat(5000)), Err(QrTooLong));
    }
}
