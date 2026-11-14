//! Native Indic-to-Latin postprocessing matching the standalone VKeyboard rules.
//! It runs after recognition and adds no model or inference allocation.
use serde::Deserialize;
use std::{collections::HashMap, sync::OnceLock};
use unicode_normalization::UnicodeNormalization;
#[derive(Deserialize)]
struct Maps {
    consonants: HashMap<String, String>,
    vowels: HashMap<String, (String, Option<String>)>,
    independent: HashMap<String, String>,
}
fn maps() -> &'static Maps {
    static MAPS: OnceLock<Maps> = OnceLock::new();
    MAPS.get_or_init(|| serde_json::from_str(include_str!("romanization.json")).unwrap())
}
#[derive(Default)]
struct Unit {
    cluster: Option<Vec<String>>,
    vowel: Option<String>,
    tail: String,
}
fn consonant(chars: &[char], i: &mut usize) -> Option<String> {
    let mut value = chars.get(*i)?.to_string();
    if !maps().consonants.contains_key(&value) {
        return None;
    }
    *i += 1;
    if chars.get(*i) == Some(&'़') {
        let form = format!("{value}़");
        if maps().consonants.contains_key(&form) {
            value = form;
        }
        *i += 1;
    }
    Some(value)
}
fn word(text: &str, hindi: bool) -> String {
    let chars: Vec<_> = text.nfd().collect();
    let mut units = Vec::<Unit>::new();
    let mut i = 0;
    while i < chars.len() {
        if let Some(c) = consonant(&chars, &mut i) {
            let mut cluster = vec![c];
            let mut vowel = Some(String::new());
            while i < chars.len() {
                let n = chars[i];
                if n == '्' {
                    i += 1;
                    if let Some(c) = consonant(&chars, &mut i) {
                        cluster.push(c);
                        continue;
                    }
                    vowel = None;
                    break;
                }
                if n == '़' {
                    i += 1;
                    continue;
                }
                if maps().vowels.contains_key(&n.to_string()) {
                    vowel = Some(n.to_string());
                    i += 1;
                }
                break;
            }
            units.push(Unit {
                cluster: Some(cluster),
                vowel,
                ..Default::default()
            });
        } else if let Some(v) = maps().independent.get(&chars[i].to_string()) {
            units.push(Unit {
                cluster: Some(vec![]),
                vowel: Some(v.clone()),
                ..Default::default()
            });
            i += 1;
        } else if matches!(chars[i], 'ं' | 'ँ' | 'ः') && !units.is_empty() {
            units
                .last_mut()
                .unwrap()
                .tail
                .push(if chars[i] == 'ः' { 'h' } else { 'n' });
            i += 1;
        } else {
            units.push(Unit {
                vowel: Some(chars[i].to_string()),
                ..Default::default()
            });
            i += 1;
        }
    }
    let letters: Vec<_> = units
        .iter()
        .enumerate()
        .filter(|(_, u)| u.cluster.is_some())
        .map(|(i, _)| i)
        .collect();
    let mut deleted = vec![false; letters.len()];
    let inherent = |u: &Unit| {
        u.vowel.as_deref() == Some("") && u.cluster.as_ref().is_some_and(|c| !c.is_empty())
    };
    if letters.len() > 1 {
        let last = units.get(*letters.last().unwrap()).unwrap();
        if inherent(last) && last.tail.is_empty() {
            deleted[letters.len() - 1] = true;
        }
    }
    for k in (1..letters.len().saturating_sub(1)).rev() {
        let current = &units[letters[k]];
        if inherent(current)
            && current.tail.is_empty()
            && current.cluster.as_ref().unwrap().len() == 1
            && units[letters[k - 1]].vowel.is_some()
            && !deleted[k - 1]
            && units[letters[k + 1]].vowel.is_some()
            && !deleted[k + 1]
        {
            deleted[k] = true;
        }
    }
    let (mut out, mut k) = (String::new(), 0usize);
    for unit in &units {
        let Some(cluster) = &unit.cluster else {
            out.push_str(unit.vowel.as_deref().unwrap_or_default());
            continue;
        };
        let index = k;
        k += 1;
        for consonant in cluster {
            out.push_str(
                maps()
                    .consonants
                    .get(consonant)
                    .map(String::as_str)
                    .unwrap_or_default(),
            );
        }
        let Some(vowel) = &unit.vowel else {
            continue;
        };
        if deleted[index] {
            continue;
        }
        if let Some((short, long)) = maps().vowels.get(vowel) {
            let closed = index + 1 == letters.len().saturating_sub(1)
                && (units[letters[index + 1]].vowel.is_none() || deleted[index + 1]);
            let initial = hindi && index == 0 && cluster.is_empty();
            out.push_str(if initial || (closed && unit.tail.is_empty()) {
                long.as_deref().unwrap_or(short)
            } else {
                short
            });
        }
        out.push_str(&unit.tail);
    }
    out
}
fn indic(c: char) -> bool {
    ('\u{900}'..='\u{d7f}').contains(&c)
}
pub fn latin(text: &str) -> String {
    let had_indic = text.chars().any(indic);
    let chars: Vec<_> = text.chars().collect();
    let (mut out, mut at) = (String::new(), 0);
    while at < chars.len() {
        if !indic(chars[at]) {
            out.push(chars[at]);
            at += 1;
            continue;
        }
        let end = (at..chars.len())
            .find(|i| !indic(chars[*i]))
            .unwrap_or(chars.len());
        let hindi = chars[at..end]
            .iter()
            .all(|c| ('\u{900}'..='\u{97f}').contains(c));
        let mut converted = String::new();
        for c in &chars[at..end] {
            let mut cp = *c as u32;
            for base in [0x980, 0xa00, 0xa80, 0xb00, 0xb80, 0xc00, 0xc80, 0xd00] {
                if (base..base + 0x80).contains(&cp) {
                    cp = cp - base + 0x900;
                    break;
                }
            }
            let c = char::from_u32(cp).unwrap_or(*c);
            match c {
                '।' | '॥' | '॰' => converted.push('.'),
                '०'..='९' => converted.push(char::from(b'0' + (cp - 0x966) as u8)),
                _ => converted.push(c),
            }
        }
        let mut fragment = String::new();
        for c in converted.chars() {
            if ('\u{900}'..='\u{97f}').contains(&c) {
                fragment.push(c);
            } else {
                out.push_str(&word(&fragment, hindi));
                fragment.clear();
                out.push(c);
            }
        }
        out.push_str(&word(&fragment, hindi));
        at = end;
    }
    let mut stripped = String::new();
    for c in out.chars() {
        if c as u32 > 255 {
            let ascii: String = c.to_string().nfkd().filter(char::is_ascii).collect();
            if ascii.is_empty() {
                stripped.push(c);
            } else {
                stripped.push_str(&ascii);
            }
        } else {
            stripped.push(c);
        }
    }
    if !had_indic {
        return stripped;
    }
    let mut sentence = true;
    stripped
        .chars()
        .map(|c| {
            let out = if sentence && c.is_ascii_lowercase() {
                c.to_ascii_uppercase()
            } else {
                c
            };
            if c.is_ascii_alphabetic() {
                sentence = false;
            } else if matches!(c, '.' | '!' | '?') {
                sentence = true;
            }
            out
        })
        .collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn matches_standalone_hinglish_examples() {
        for (src, want) in [
            (
                "क्या आप मेरी मदद कर सकते हैं?",
                "Kya aap meri madad kar sakte hain?",
            ),
            ("मुझे कल सुबह दिल्ली जाना है।", "Mujhe kal subah dilli jana hai."),
            ("मेरा नाम नितिन है", "Mera naam nitin hai"),
            ("मैं समझना चाहता हूँ", "Main samajhna chahta hun"),
            ("आज रात हम बाज़ार जाएंगे", "Aaj raat ham bazaar jaenge"),
            ("Hello दोस्तों, meeting कल है", "Hello doston, meeting kal hai"),
            ("আমি ভালো আছি", "Ami bhalo achhi"),
            ("Kjā mērīmā dot", "Kja merima dot"),
        ] {
            assert_eq!(latin(src), want, "{src}");
        }
    }
}
