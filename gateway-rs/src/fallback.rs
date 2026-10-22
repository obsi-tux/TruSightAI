//! Templated en/hi fallback content per scam_type (used when the LLM is
//! unavailable or its output fails schema validation — full LLM layer lands in P2).
use crate::contract::DetectSignal;

pub struct Fallback {
    pub explanation: &'static str,
    pub actions: &'static [&'static str],
}

const GENERIC_EN: Fallback = Fallback {
    explanation: "This message shows several patterns commonly used in scams.",
    actions: &[
        "Do not click links or share personal details",
        "Verify through an official channel you know",
        "If unsure, do nothing and ask someone you trust",
    ],
};

const GENERIC_HI: Fallback = Fallback {
    explanation: "इस संदेश में धोखाधड़ी के कई आम पैटर्न दिख रहे हैं।",
    actions: &[
        "लिंक न खोलें और व्यक्तिगत जानकारी न भेजें",
        "किसी आधिकारिक माध्यम से स्वयं पुष्टि करें",
        "शक हो तो कुछ न करें और विश्वसनीय व्यक्ति से सलाह लें",
    ],
};

/// NOTE: helpline numbers live only in shared/config.json as "TODO" markers.
/// Never hardcode them here (TECHNOLOGY.md section 8 / forbidden list).
pub fn template(scam_type: &str, lang: &str) -> Fallback {
    let hi = lang == "hi";
    match scam_type {
        "otp_fraud" => {
            if hi {
                Fallback {
                    explanation: "यह संदेश आपका OTP, PIN या CVV माँग रहा है। बैंक और पुलिस कभी ये नहीं माँगते।",
                    actions: &[
                        "OTP/PIN/CVV किसी से शेयर न करें",
                        "संदेश का कोई लिंक न खोलें",
                        "अपने बैंक की आधिकारिक एप में खुद लॉगिन करके जाँचें",
                    ],
                }
            } else {
                Fallback {
                    explanation: "This message asks for your OTP, PIN or CVV. Banks and police never ask for these.",
                    actions: &[
                        "Never share OTP/PIN/CVV with anyone",
                        "Do not click any links in the message",
                        "Verify directly in your bank's official app",
                    ],
                }
            }
        }
        "vishing" => {
            if hi {
                Fallback {
                    explanation: "यह कॉल-स्क्रिप्ट जैसा संदेश दबाव बनाकर remote-access ऐप इंस्टॉल करने या पैसे भेजने के लिए उकसाता है।",
                    actions: &[
                        "कोई remote-access ऐप इंस्टॉल न करें",
                        "कॉल छोड़ दें और आधिकारिक नंबर पर खुद कॉल करें",
                        "गोपनीयता रखने की माँग को न मानें",
                    ],
                }
            } else {
                Fallback {
                    explanation: "This call-script style message uses urgency to push you into installing a remote-access app or sending money.",
                    actions: &[
                        "Do not install any remote-access app",
                        "End the call and dial the official number yourself",
                        "Refuse any demand to keep it secret",
                    ],
                }
            }
        }
        "phishing_link" => {
            if hi {
                Fallback {
                    explanation: "इस संदेश में संदिग्ध लिंक है जो आपके क्रेडेंशियल चुरा सकता है।",
                    actions: &[
                        "लिंक न खोलें",
                        "भेजने वाले से किसी परिचित माध्यम से पुष्टि करें",
                        "कोई जानकारी भरने से पहले डोमेन जाँचें",
                    ],
                }
            } else {
                Fallback {
                    explanation: "This message contains a suspicious link that may steal your credentials.",
                    actions: &[
                        "Do not open the link",
                        "Confirm with the sender through a known channel",
                        "Check the real domain before entering any details",
                    ],
                }
            }
        }
        "kyc_bank" => {
            if hi {
                Fallback {
                    explanation: "\"KYC/आधार/PAN अपडेट न करने पर खाता बंद\" वाली धमकी एक आम फ्रॉड पैटर्न है।",
                    actions: &[
                        "लिंक पर जानकारी न भरें",
                        "ज़रूरत हो तो बैंक शाखा में स्वयं जाएँ",
                        "अपडेट केवल आधिकारिक ऐप से करें",
                    ],
                }
            } else {
                Fallback {
                    explanation: "Threats that your account will be blocked unless you 'update KYC/Aadhaar/PAN' are a common scam pattern.",
                    actions: &[
                        "Do not enter details on the linked page",
                        "Visit your bank branch in person if needed",
                        "Use only the official app for updates",
                    ],
                }
            }
        }
        "lottery" => {
            if hi {
                Fallback {
                    explanation: "बिना भाग लिए 'इनाम' और पहले 'फ़ीस' भेजने की माँग धोखाधड़ी का संकेत है।",
                    actions: &[
                        "कोई फ़ीस न भेजें",
                        "लिंक/नंबर पर कॉल न करें",
                        "आधिकारिक वेबसाइट पर खुद जाँचें",
                    ],
                }
            } else {
                Fallback {
                    explanation: "An 'unclaimed prize' that requires an upfront fee is a classic lottery scam.",
                    actions: &[
                        "Do not pay any fee to claim a prize",
                        "Do not call the listed number or open links",
                        "Check the official website yourself",
                    ],
                }
            }
        }
        "fake_job" => {
            if hi {
                Fallback {
                    explanation: "नौकरी के बदले पहले रजिस्ट्रेशन/ट्रेनिंग फ़ीस माँगना आम नौकरी-फ्रॉड है।",
                    actions: &[
                        "कोई अग्रिम फ़ीस न भेजें",
                        "कंपनी की आधिकारिक साइट जाँचें",
                        "पहचान-प्रमाण असत्यापित संपर्कों को न भेजें",
                    ],
                }
            } else {
                Fallback {
                    explanation: "Asking job seekers to pay a registration/training fee upfront is a common fake-job scam.",
                    actions: &[
                        "Do not send any advance fee",
                        "Verify the company on its official site",
                        "Do not send identity documents to unverified contacts",
                    ],
                }
            }
        }
        "parcel" => {
            if hi {
                Fallback {
                    explanation: "अपरिचित पार्सल के लिए छोटी 'कस्टम/डिलीवरी फ़ीस' माँगने वाला संदेश फ्रॉड हो सकता है।",
                    actions: &[
                        "लिंक से फ़ीस न भरें",
                        "कूरियर की आधिकारिक साइट पर ट्रैकिंग नंबर जाँचें",
                        "शक हो तो पार्सल लेने से इनकार करें",
                    ],
                }
            } else {
                Fallback {
                    explanation: "A small 'customs/delivery fee' for a parcel you don't recognise is a common parcel scam.",
                    actions: &[
                        "Do not pay via the message link",
                        "Check the tracking number on the courier's official site",
                        "Refuse the parcel if unsure",
                    ],
                }
            }
        }
        "investment" => {
            if hi {
                Fallback {
                    explanation: "गारंटीड ऊँचे रिटर्न और जल्दी पैसा भेजने का दबाव निवेश-फ्रॉड के लक्षण हैं।",
                    actions: &[
                        "पैसे न भेजें",
                        "SEBI रजिस्ट्रेशन खुद जाँचें",
                        "बिना दबाव में सलाहकार से बात करें",
                    ],
                }
            } else {
                Fallback {
                    explanation: "Guaranteed high returns plus pressure to send money quickly are investment-scam hallmarks.",
                    actions: &[
                        "Do not transfer money",
                        "Verify regulatory registration yourself",
                        "Consult an independent adviser without time pressure",
                    ],
                }
            }
        }
        "impersonation" => {
            if hi {
                Fallback {
                    explanation: "कोई परिचित/अधिकारी बनकर माँग की जा रही है — पहचान की पुष्टि न होने तक रुकें।",
                    actions: &[
                        "किसी भी ट्रांसफ़र से पहले पुराने नंबर पर वापस कॉल करें",
                        "वीडियो/फ़ोन से पहचान स्वतंत्र रूप से जाँचें",
                        "जल्दबाज़ी में निर्णय न लें",
                    ],
                }
            } else {
                Fallback {
                    explanation: "Someone appears to be impersonating a known person or authority — pause until identity is confirmed.",
                    actions: &[
                        "Call back on a previously known number before any transfer",
                        "Verify identity by video/phone independently",
                        "Do not decide under time pressure",
                    ],
                }
            }
        }
        _ => {
            if hi {
                GENERIC_HI
            } else {
                GENERIC_EN
            }
        }
    }
}

/// Map detect-py signals to a contract scam_type using rule ids from
/// shared/rules.json (falls back to "none").
pub fn best_scam_type(signals: &[DetectSignal]) -> String {
    let mut best: Option<(f64, &str)> = None;
    for s in signals.iter().filter(|s| s.weight > 0.0) {
        let st = match s.detail.as_str() {
            "" | "benign_phrase" | "no_signal" => continue,
            d if crate::contract::SCAM_TYPES.contains(&d) => d,
            _ => match s.signal.as_str() {
                "otp_fishing" | "otp_fishing_hi" => "otp_fraud",
                "remote_access_app" | "police_demand" | "courier_vishing" | "secrecy_demand" => "vishing",
                "url_shortener" | "suspicious_tld" | "ip_host_url" | "lookalike_domain" | "whatsapp_link" => {
                    "phishing_link"
                }
                "aadhaar_pan_demand" | "bank_impersonation" => "kyc_bank",
                "prize_claim" => "lottery",
                "loan_upfront_fee" => "fake_job",
                "payment_demand_en" | "payment_demand_hi" | "urgency_en" | "urgency_hi" => "impersonation",
                _ => continue,
            },
        };
        if best.map_or(true, |(w, _)| s.weight > w) {
            best = Some((s.weight, st));
        }
    }
    best.map(|(_, st)| st.to_string()).unwrap_or_else(|| "none".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::DetectSignal;

    #[test]
    fn every_scam_type_has_a_template() {
        for st in crate::contract::SCAM_TYPES {
            let f = template(st, "en");
            assert!(!f.explanation.is_empty());
            assert!(f.actions.len() >= 2, "{st}");
            let f = template(st, "hi");
            assert!(!f.explanation.is_empty());
        }
    }
    #[test]
    fn scam_type_from_signals_prefers_highest_weight() {
        let sigs = vec![
            DetectSignal { signal: "urgency_en".into(), detail: "impersonation".into(), weight: 20.0 },
            DetectSignal { signal: "otp_fishing".into(), detail: "otp_fraud".into(), weight: 60.0 },
        ];
        assert_eq!(best_scam_type(&sigs), "otp_fraud");
    }
    #[test]
    fn benign_only_signals_give_none() {
        let sigs = vec![DetectSignal {
            signal: "benign_otp_protect".into(),
            detail: "benign_phrase".into(),
            weight: -30.0,
        }];
        assert_eq!(best_scam_type(&sigs), "none");
    }
}
