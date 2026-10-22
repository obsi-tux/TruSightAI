//! Pure score fusion per the frozen contract.
//! Weights: rule .30, url .25, ml .30, llm .15. Missing components are dropped
//! and remaining weights renormalized. GREEN < 35, AMBER 35-70, RED > 70.
//! force_red floors the score at 71. The LLM can add evidence but never lower
//! a deterministic score (enforced by `llm_floor`).

pub const W_RULE: f64 = 0.30;
pub const W_URL: f64 = 0.25;
pub const W_ML: f64 = 0.30;
pub const W_LLM: f64 = 0.15;

/// Scores at or below this are GREEN; at or below AMBER_MAX are AMBER; above is RED.
pub const GREEN_MAX: f64 = 34.999;
pub const AMBER_MAX: f64 = 70.0;
pub const FORCE_RED_FLOOR: f64 = 71.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Label {
    Green,
    Amber,
    Red,
}

impl Label {
    pub fn as_str(self) -> &'static str {
        match self {
            Label::Green => "GREEN",
            Label::Amber => "AMBER",
            Label::Red => "RED",
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Scores {
    pub rule: f64,
    pub url: f64,
    /// `None` when the component is missing (model file absent, LLM down).
    pub ml: Option<f64>,
    pub llm: Option<f64>,
    pub force_red: bool,
    /// Deterministic fused score computed WITHOUT the llm component. When set,
    /// the fused result is never lowered below it ("LLM cannot lower a
    /// deterministic score"). Computed by the caller via `fuse(&without_llm)`.
    pub llm_floor: Option<f64>,
}

fn clamp100(v: f64) -> f64 {
    if v.is_nan() {
        0.0
    } else {
        v.clamp(0.0, 100.0)
    }
}

/// Fuse component scores into (score, label). Pure function; no I/O.
pub fn fuse(s: &Scores) -> (u8, Label) {
    let mut num = W_RULE * clamp100(s.rule) + W_URL * clamp100(s.url);
    let mut den = W_RULE + W_URL;
    if let Some(m) = s.ml {
        num += W_ML * clamp100(m);
        den += W_ML;
    }
    if let Some(l) = s.llm {
        num += W_LLM * clamp100(l);
        den += W_LLM;
    }
    let mut score = (num / den).round().clamp(0.0, 100.0);
    // The LLM may raise risk, never lower a deterministic score.
    if let Some(floor) = s.llm_floor {
        score = score.max(clamp100(floor));
    }
    if s.force_red && score < FORCE_RED_FLOOR {
        score = FORCE_RED_FLOOR;
    }
    let label = if score <= GREEN_MAX {
        Label::Green
    } else if score <= AMBER_MAX {
        Label::Amber
    } else {
        Label::Red
    };
    (score as u8, label)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sc(rule: f64, url: f64, ml: Option<f64>, llm: Option<f64>) -> Scores {
        Scores { rule, url, ml, llm, force_red: false, llm_floor: None }
    }

    // ---- basic behaviour -------------------------------------------------
    #[test]
    fn t01_all_zero_is_green() {
        assert_eq!(fuse(&sc(0., 0., Some(0.), Some(0.))).1, Label::Green);
    }
    #[test]
    fn t02_force_red_floors_score() {
        let s = Scores { rule: 0., url: 0., ml: Some(0.), llm: Some(0.), force_red: true, llm_floor: None };
        let (v, l) = fuse(&s);
        assert!(v >= 71);
        assert_eq!(l, Label::Red);
    }
    #[test]
    fn t03_missing_ml_renormalizes() {
        let (v, _) = fuse(&sc(100., 100., None, None));
        assert_eq!(v, 100);
    }
    #[test]
    fn t04_out_of_range_is_clamped() {
        assert_eq!(fuse(&sc(500., 500., None, None)).0, 100);
        assert_eq!(fuse(&sc(-50., -50., Some(-10.), None)).0, 0);
    }
    #[test]
    fn t05_boundary_amber() {
        assert_eq!(fuse(&sc(50., 50., Some(50.), Some(50.))).1, Label::Amber);
    }

    // ---- benign controls (must NOT be RED) --------------------------------
    #[test]
    fn t06_benign_bank_alert_low_scores_is_green() {
        // "Your OTP is 123456. Do not share it with anyone." -> rules discount it.
        let (v, l) = fuse(&sc(10., 0., Some(5.), None));
        assert_eq!(l, Label::Green);
        assert!(v < 35);
    }
    #[test]
    fn t07_benign_delivery_update_is_green() {
        let (v, l) = fuse(&sc(5., 0., Some(12.), Some(10.)));
        assert_eq!(l, Label::Green);
        assert!(v < 35);
    }
    #[test]
    fn t08_personal_message_with_one_url_stays_green_or_amber() {
        let (_, l) = fuse(&sc(0., 25., Some(10.), None));
        assert!(l != Label::Red);
    }

    // ---- LLM cannot lower deterministic score -----------------------------
    #[test]
    fn t09_llm_cannot_lower_deterministic_score() {
        // deterministic (rule+url+ml) fusion:
        let det = fuse(&sc(90., 80., Some(85.), None)).0 as f64;
        let s = Scores { rule: 90., url: 80., ml: Some(85.), llm: Some(0.), force_red: false, llm_floor: Some(det) };
        let (v, l) = fuse(&s);
        assert!((v as f64) >= det);
        assert_eq!(l, Label::Red);
    }
    #[test]
    fn t10_llm_can_raise_toward_red_but_not_past_fused_math() {
        let (v, _) = fuse(&sc(60., 60., Some(60.), Some(100.)));
        // weighted avg of 60/60/60/100 = (18+15+18+15)/1.0 = 66
        assert_eq!(v, 66);
    }

    // ---- negative / edge inputs -------------------------------------------
    #[test]
    fn t11_negative_inputs_clamp_to_zero() {
        let (v, l) = fuse(&sc(-100., -100., Some(-100.), Some(-100.)));
        assert_eq!(v, 0);
        assert_eq!(l, Label::Green);
    }
    #[test]
    fn t12_nan_inputs_are_treated_as_zero() {
        let (v, _) = fuse(&sc(f64::NAN, 0., Some(f64::NAN), None));
        assert_eq!(v, 0);
    }
    #[test]
    fn t13_only_rule_present_renormalizes_to_rule() {
        let (v, l) = fuse(&Scores { rule: 80., url: 0., ml: None, llm: None, force_red: false, llm_floor: None });
        // url counts as present (0) per contract shape; rule .30 vs url .25 -> 48
        assert_eq!(v, 48);
        assert_eq!(l, Label::Amber);
    }
    #[test]
    fn t14_amber_upper_boundary() {
        // exactly 70 stays AMBER, 71 is RED
        let s = Scores { rule: 70., url: 70., ml: Some(70.), llm: Some(70.), force_red: false, llm_floor: None };
        assert_eq!(fuse(&s).1, Label::Amber);
        let s = Scores { rule: 71., url: 71., ml: Some(71.), llm: Some(71.), force_red: false, llm_floor: None };
        assert_eq!(fuse(&s).1, Label::Red);
    }
    #[test]
    fn t15_green_upper_boundary() {
        let s = Scores { rule: 35., url: 35., ml: Some(35.), llm: Some(35.), force_red: false, llm_floor: None };
        assert_eq!(fuse(&s).1, Label::Amber);
        let s = Scores { rule: 34., url: 34., ml: Some(34.), llm: Some(34.), force_red: false, llm_floor: None };
        assert_eq!(fuse(&s).1, Label::Green);
    }
    #[test]
    fn t16_force_red_keeps_higher_natural_score() {
        let s = Scores { rule: 95., url: 90., ml: Some(92.), llm: None, force_red: true, llm_floor: None };
        let (v, l) = fuse(&s);
        assert!(v > 71);
        assert_eq!(l, Label::Red);
    }
    #[test]
    fn t17_llm_floor_applies_even_when_llm_absent() {
        let s = Scores { rule: 10., url: 10., ml: None, llm: None, force_red: false, llm_floor: Some(40.) };
        assert_eq!(fuse(&s).0, 40);
    }
    #[test]
    fn t18_mixed_missing_ml_and_llm() {
        // rule 100, url 0, others missing -> 30/55*100 ~ 55 AMBER
        let (v, l) = fuse(&sc(100., 0., None, None));
        assert_eq!(v, 55);
        assert_eq!(l, Label::Amber);
    }
}
