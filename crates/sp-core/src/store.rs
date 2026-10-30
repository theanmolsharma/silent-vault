//! Persisted application state: label names and indices, network, identity fingerprint.
//!
//! Nothing secret is stored. Addresses are re-derived on every launch from the app seed and the
//! label integers kept here, so this file alone reveals label names but no keys or addresses.
//!
//! Label integers are allocated from 1 upwards and never reused, even after a label is deleted:
//! someone may still pay to a deleted label's address, and BIP352 scanners need the full range
//! `1..=max_issued_label` to find those payments. `m = 0` (change) is never handed out.

use core::fmt;

use serde::{Deserialize, Serialize};

use crate::keys::hex_lower;
use crate::network::Network;

/// Current on-disk format version.
pub const STATE_VERSION: u32 = 1;

/// Most labels the app will keep. Keeps the on-device list and the export manageable.
pub const MAX_LABELS: usize = 50;

/// Maximum label name length in characters.
pub const MAX_LABEL_NAME_CHARS: usize = 32;

/// First label integer handed to users (`m = 0` is reserved for change).
pub const FIRST_USER_LABEL: u32 = 1;

/// A user-visible receiving label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabelRecord {
    /// BIP352 label integer `m` (always at least 1).
    pub m: u32,
    /// Human-readable name.
    pub name: String,
}

/// Why a label name was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabelNameError {
    /// Empty after trimming.
    Empty,
    /// More than [`MAX_LABEL_NAME_CHARS`] characters.
    TooLong,
    /// Control or other non-printable character.
    InvalidCharacter(char),
    /// Another label already uses this name (case-insensitive).
    Duplicate,
}

impl fmt::Display for LabelNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LabelNameError::Empty => f.write_str("Enter a label name."),
            LabelNameError::TooLong => write!(f, "Use at most {MAX_LABEL_NAME_CHARS} characters."),
            LabelNameError::InvalidCharacter(_) => f.write_str("The name contains an unsupported character."),
            LabelNameError::Duplicate => f.write_str("A label with this name already exists."),
        }
    }
}

impl std::error::Error for LabelNameError {}

/// Errors loading or changing the state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// The bytes are not valid JSON for this format.
    Malformed(String),
    /// Written by a newer (or unknown) app version.
    UnsupportedVersion(u32),
    /// Parsed but violates an invariant.
    Invalid(&'static str),
    /// A label name was rejected.
    Name(LabelNameError),
    /// [`MAX_LABELS`] reached.
    TooManyLabels,
    /// All label integers have been used.
    LabelSpaceExhausted,
    /// No label with this integer.
    UnknownLabel(u32),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Malformed(e) => write!(f, "saved data is unreadable: {e}"),
            StoreError::UnsupportedVersion(v) => write!(f, "saved data has unsupported version {v}"),
            StoreError::Invalid(e) => write!(f, "saved data is inconsistent: {e}"),
            StoreError::Name(e) => e.fmt(f),
            StoreError::TooManyLabels => write!(f, "You can keep up to {MAX_LABELS} labels."),
            StoreError::LabelSpaceExhausted => f.write_str("No label numbers are left."),
            StoreError::UnknownLabel(m) => write!(f, "label {m} does not exist"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<LabelNameError> for StoreError {
    fn from(e: LabelNameError) -> Self { StoreError::Name(e) }
}

/// Result of comparing the stored identity with the keys derived at launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityCheck {
    /// No identity was stored yet; it has now been recorded.
    New,
    /// Same master fingerprint as before.
    Match,
    /// The app seed changed (for example, the Passport was restored from a different seed).
    /// Labels still apply, but they now produce different addresses.
    Mismatch {
        /// Fingerprint recorded previously.
        stored: [u8; 4],
    },
}

/// Everything the app persists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppState {
    version: u32,
    network: Network,
    /// Hex master fingerprint of the identity the labels were created under.
    identity_fingerprint: Option<String>,
    next_label: u32,
    labels: Vec<LabelRecord>,
}

impl AppState {
    /// Fresh state: mainnet, no identity, no labels.
    pub fn new() -> Self {
        Self {
            version: STATE_VERSION,
            network: Network::Mainnet,
            identity_fingerprint: None,
            next_label: FIRST_USER_LABEL,
            labels: Vec::new(),
        }
    }

    /// Parses and validates saved bytes.
    pub fn from_json(bytes: &[u8]) -> Result<Self, StoreError> {
        #[derive(Deserialize)]
        struct Version {
            version: u32,
        }
        let version: Version =
            serde_json::from_slice(bytes).map_err(|e| StoreError::Malformed(e.to_string()))?;
        if version.version != STATE_VERSION {
            return Err(StoreError::UnsupportedVersion(version.version));
        }
        let state: AppState = serde_json::from_slice(bytes).map_err(|e| StoreError::Malformed(e.to_string()))?;
        state.validate()?;
        Ok(state)
    }

    /// Serializes for saving.
    pub fn to_json(&self) -> Vec<u8> { serde_json::to_vec_pretty(self).expect("state is always serializable") }

    fn validate(&self) -> Result<(), StoreError> {
        if self.next_label < FIRST_USER_LABEL {
            return Err(StoreError::Invalid("next label must be at least 1"));
        }
        if self.labels.len() > MAX_LABELS {
            return Err(StoreError::Invalid("too many labels"));
        }
        if let Some(fp) = &self.identity_fingerprint {
            if fp.len() != 8 || !fp.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
                return Err(StoreError::Invalid("identity fingerprint must be 8 lowercase hex digits"));
            }
        }
        for (i, label) in self.labels.iter().enumerate() {
            if label.m < FIRST_USER_LABEL || label.m >= self.next_label {
                return Err(StoreError::Invalid("label integer out of range"));
            }
            if normalize_label_name(&label.name).as_deref() != Ok(label.name.as_str()) {
                return Err(StoreError::Invalid("label name is not normalized"));
            }
            for other in &self.labels[..i] {
                if other.m == label.m {
                    return Err(StoreError::Invalid("duplicate label integer"));
                }
                if names_equal(&other.name, &label.name) {
                    return Err(StoreError::Invalid("duplicate label name"));
                }
            }
        }
        Ok(())
    }

    /// Network used for addresses and derivation.
    pub fn network(&self) -> Network { self.network }

    /// Changes the network. Labels are shared between networks.
    pub fn set_network(&mut self, network: Network) { self.network = network; }

    /// Whether first-launch setup has completed.
    pub fn is_set_up(&self) -> bool { self.identity_fingerprint.is_some() }

    /// Stored identity fingerprint, if any.
    pub fn identity_fingerprint(&self) -> Option<[u8; 4]> {
        let fp = self.identity_fingerprint.as_ref()?;
        let mut out = [0u8; 4];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&fp[2 * i..2 * i + 2], 16).ok()?;
        }
        Some(out)
    }

    /// Compares the derived identity with the stored one, recording it if none was stored.
    pub fn check_identity(&mut self, fingerprint: [u8; 4]) -> IdentityCheck {
        match self.identity_fingerprint() {
            None => {
                self.identity_fingerprint = Some(hex_lower(&fingerprint));
                IdentityCheck::New
            }
            Some(stored) if stored == fingerprint => IdentityCheck::Match,
            Some(stored) => IdentityCheck::Mismatch { stored },
        }
    }

    /// Adopts a new identity after the user acknowledged a mismatch.
    pub fn replace_identity(&mut self, fingerprint: [u8; 4]) {
        self.identity_fingerprint = Some(hex_lower(&fingerprint));
    }

    /// Labels in creation order.
    pub fn labels(&self) -> &[LabelRecord] { &self.labels }

    /// Looks up a label by integer.
    pub fn label(&self, m: u32) -> Option<&LabelRecord> { self.labels.iter().find(|l| l.m == m) }

    /// Highest label integer ever handed out (including deleted labels), if any.
    pub fn max_issued_label(&self) -> Option<u32> {
        (self.next_label > FIRST_USER_LABEL).then(|| self.next_label - 1)
    }

    /// Creates a label with the next unused integer.
    pub fn create_label(&mut self, name: &str) -> Result<&LabelRecord, StoreError> {
        let name = normalize_label_name(name)?;
        if self.labels.iter().any(|l| names_equal(&l.name, &name)) {
            return Err(LabelNameError::Duplicate.into());
        }
        if self.labels.len() >= MAX_LABELS {
            return Err(StoreError::TooManyLabels);
        }
        let m = self.next_label;
        self.next_label = m.checked_add(1).ok_or(StoreError::LabelSpaceExhausted)?;
        self.labels.push(LabelRecord { m, name });
        Ok(self.labels.last().expect("just pushed"))
    }

    /// Renames label `m`.
    pub fn rename_label(&mut self, m: u32, name: &str) -> Result<(), StoreError> {
        let name = normalize_label_name(name)?;
        if self.labels.iter().any(|l| l.m != m && names_equal(&l.name, &name)) {
            return Err(LabelNameError::Duplicate.into());
        }
        let label = self.labels.iter_mut().find(|l| l.m == m).ok_or(StoreError::UnknownLabel(m))?;
        label.name = name;
        Ok(())
    }

    /// Deletes label `m`. Its integer is not reused.
    pub fn delete_label(&mut self, m: u32) -> Result<LabelRecord, StoreError> {
        let index = self.labels.iter().position(|l| l.m == m).ok_or(StoreError::UnknownLabel(m))?;
        Ok(self.labels.remove(index))
    }
}

impl Default for AppState {
    fn default() -> Self { Self::new() }
}

/// What the app found in storage at launch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadOutcome {
    /// Nothing saved yet (first launch, or app data was wiped).
    Fresh(AppState),
    /// Saved state loaded and validated.
    Loaded(AppState),
    /// Saved bytes were unreadable. The app keeps a copy of them and starts from a fresh state
    /// rather than overwriting the only copy.
    Corrupt {
        /// Why the saved bytes were rejected.
        error: StoreError,
        /// Fresh state to continue with.
        state: AppState,
    },
}

impl LoadOutcome {
    /// The state to run with.
    pub fn into_state(self) -> AppState {
        match self {
            LoadOutcome::Fresh(s) | LoadOutcome::Loaded(s) | LoadOutcome::Corrupt { state: s, .. } => s,
        }
    }
}

/// Interprets the saved bytes (`None` or empty when no file exists).
pub fn load_state(saved: Option<&[u8]>) -> LoadOutcome {
    match saved {
        None | Some([]) => LoadOutcome::Fresh(AppState::new()),
        Some(bytes) => match AppState::from_json(bytes) {
            Ok(state) => LoadOutcome::Loaded(state),
            Err(error) => LoadOutcome::Corrupt { error, state: AppState::new() },
        },
    }
}

/// Trims and collapses whitespace, then checks length and characters.
pub fn normalize_label_name(input: &str) -> Result<String, LabelNameError> {
    if let Some(c) = input.chars().find(|c| c.is_control() || is_invisible(*c)) {
        return Err(LabelNameError::InvalidCharacter(c));
    }
    let name = input.split_whitespace().collect::<Vec<_>>().join(" ");
    if name.is_empty() {
        return Err(LabelNameError::Empty);
    }
    if name.chars().count() > MAX_LABEL_NAME_CHARS {
        return Err(LabelNameError::TooLong);
    }
    Ok(name)
}

fn names_equal(a: &str, b: &str) -> bool { a.to_lowercase() == b.to_lowercase() }

/// Zero-width and bidi-control characters that would make two names look alike.
fn is_invisible(c: char) -> bool {
    matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2064}' | '\u{FEFF}')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_start_at_one_and_are_never_reused() {
        let mut s = AppState::new();
        assert_eq!(s.max_issued_label(), None);
        assert_eq!(s.create_label("Personal").unwrap().m, 1);
        assert_eq!(s.create_label("Donations").unwrap().m, 2);
        s.delete_label(2).unwrap();
        assert_eq!(s.create_label("Business").unwrap().m, 3);
        assert_eq!(s.max_issued_label(), Some(3));
        assert!(s.labels().iter().all(|l| l.m != 0));
    }

    #[test]
    fn name_validation() {
        assert_eq!(normalize_label_name("  Open   source  ").unwrap(), "Open source");
        assert_eq!(normalize_label_name("   "), Err(LabelNameError::Empty));
        assert_eq!(normalize_label_name(""), Err(LabelNameError::Empty));
        assert_eq!(normalize_label_name(&"x".repeat(33)), Err(LabelNameError::TooLong));
        assert!(normalize_label_name(&"x".repeat(32)).is_ok());
        assert!(normalize_label_name(&"é".repeat(32)).is_ok());
        assert_eq!(normalize_label_name("a\nb"), Err(LabelNameError::InvalidCharacter('\n')));
        assert_eq!(normalize_label_name("a\u{200B}b"), Err(LabelNameError::InvalidCharacter('\u{200B}')));
        assert_eq!(normalize_label_name("a\u{202E}b"), Err(LabelNameError::InvalidCharacter('\u{202E}')));
    }

    #[test]
    fn duplicate_names_are_rejected_case_insensitively() {
        let mut s = AppState::new();
        s.create_label("Conference").unwrap();
        assert_eq!(s.create_label("conference ").unwrap_err(), StoreError::Name(LabelNameError::Duplicate));
        let m = s.create_label("Business").unwrap().m;
        assert_eq!(s.rename_label(m, "CONFERENCE").unwrap_err(), StoreError::Name(LabelNameError::Duplicate));
        s.rename_label(m, "business").unwrap();
        assert_eq!(s.label(m).unwrap().name, "business");
    }

    #[test]
    fn unknown_labels() {
        let mut s = AppState::new();
        assert_eq!(s.rename_label(4, "x").unwrap_err(), StoreError::UnknownLabel(4));
        assert_eq!(s.delete_label(4).unwrap_err(), StoreError::UnknownLabel(4));
    }

    #[test]
    fn label_limit() {
        let mut s = AppState::new();
        for i in 0..MAX_LABELS {
            s.create_label(&format!("L{i}")).unwrap();
        }
        assert_eq!(s.create_label("one more").unwrap_err(), StoreError::TooManyLabels);
    }

    #[test]
    fn json_round_trip() {
        let mut s = AppState::new();
        s.set_network(Network::Testnet);
        assert_eq!(s.check_identity([1, 2, 3, 4]), IdentityCheck::New);
        s.create_label("Personal").unwrap();
        s.create_label("Donations").unwrap();
        s.delete_label(1).unwrap();
        let loaded = AppState::from_json(&s.to_json()).unwrap();
        assert_eq!(loaded, s);
        assert_eq!(loaded.max_issued_label(), Some(2));
        assert_eq!(loaded.identity_fingerprint(), Some([1, 2, 3, 4]));
    }

    #[test]
    fn identity_check() {
        let mut s = AppState::new();
        assert!(!s.is_set_up());
        assert_eq!(s.check_identity([9; 4]), IdentityCheck::New);
        assert!(s.is_set_up());
        assert_eq!(s.check_identity([9; 4]), IdentityCheck::Match);
        assert_eq!(s.check_identity([8; 4]), IdentityCheck::Mismatch { stored: [9; 4] });
        s.replace_identity([8; 4]);
        assert_eq!(s.check_identity([8; 4]), IdentityCheck::Match);
    }

    #[test]
    fn rejects_corrupt_or_foreign_data() {
        assert!(matches!(AppState::from_json(b""), Err(StoreError::Malformed(_))));
        assert!(matches!(AppState::from_json(b"{not json"), Err(StoreError::Malformed(_))));
        assert!(matches!(AppState::from_json(b"[]"), Err(StoreError::Malformed(_))));
        let good = String::from_utf8(AppState::new().to_json()).unwrap();
        let v2 = good.replace("\"version\": 1", "\"version\": 2");
        assert_eq!(AppState::from_json(v2.as_bytes()), Err(StoreError::UnsupportedVersion(2)));
        let extra = good.replacen('{', "{\"secret\": \"x\",", 1);
        assert!(matches!(AppState::from_json(extra.as_bytes()), Err(StoreError::Malformed(_))));
        let net = good.replace("mainnet", "regtest");
        assert!(matches!(AppState::from_json(net.as_bytes()), Err(StoreError::Malformed(_))));
    }

    #[test]
    fn rejects_inconsistent_data() {
        let base = |labels: &str, next: u32, fp: &str| {
            format!(r#"{{"version":1,"network":"mainnet","identity_fingerprint":{fp},"next_label":{next},"labels":{labels}}}"#)
        };
        let ok = base(r#"[{"m":1,"name":"A"}]"#, 2, "null");
        assert!(AppState::from_json(ok.as_bytes()).is_ok());
        let cases = [
            base(r#"[{"m":0,"name":"A"}]"#, 2, "null"),                          // change label
            base(r#"[{"m":2,"name":"A"}]"#, 2, "null"),                          // >= next_label
            base(r#"[{"m":1,"name":"A"},{"m":1,"name":"B"}]"#, 3, "null"),       // duplicate m
            base(r#"[{"m":1,"name":"A"},{"m":2,"name":"a"}]"#, 3, "null"),       // duplicate name
            base(r#"[{"m":1,"name":" A"}]"#, 2, "null"),                         // not normalized
            base("[]", 0, "null"),                                               // bad next_label
            base("[]", 1, r#""ABCDEF01""#),                                      // uppercase fp
            base("[]", 1, r#""abc""#),                                           // short fp
        ];
        for case in &cases {
            assert!(matches!(AppState::from_json(case.as_bytes()), Err(StoreError::Invalid(_))), "{case}");
        }
    }
}
