use std::collections::BTreeMap;
use std::fmt::Write;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoldedStack {
    pub stack: Vec<String>,
    pub value: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FlameNode {
    pub name: String,
    pub self_value: u64,
    pub total_value: u64,
    pub delta_value: i64,
    pub delta_pct: f64,
    pub children: Vec<FlameNode>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FlameGraph {
    pub title: String,
    pub unit: String,
    pub total_value: u64,
    pub differential: bool,
    pub root: FlameNode,
}

/// Parse Brendan Gregg `.folded` lines (`frame1;frame2;frame3 1234`).
#[must_use]
pub fn parse_folded(folded: &str) -> Vec<FoldedStack> {
    let mut agg: BTreeMap<Vec<String>, u64> = BTreeMap::new();
    for line in folded.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((path_part, count_part)) = trimmed.rsplit_once(' ') else {
            continue;
        };
        let Ok(val) = count_part.trim().parse::<u64>() else {
            continue;
        };
        if val == 0 {
            continue;
        }
        let frames: Vec<String> = path_part
            .split(';')
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        if !frames.is_empty() {
            *agg.entry(frames).or_insert(0) += val;
        }
    }
    agg.into_iter()
        .map(|(stack, value)| FoldedStack { stack, value })
        .collect()
}

/// Format stacks into deterministic `.folded` text (`a;b;c 42\n`).
#[must_use]
pub fn to_folded(stacks: &[FoldedStack]) -> String {
    let mut merged: BTreeMap<String, u64> = BTreeMap::new();
    for s in stacks {
        if s.stack.is_empty() || s.value == 0 {
            continue;
        }
        *merged.entry(s.stack.join(";")).or_insert(0) += s.value;
    }
    let mut out = String::new();
    for (path, val) in merged {
        let _ = writeln!(out, "{path} {val}");
    }
    out
}

#[derive(Default)]
struct TrieBuilder {
    self_val: u64,
    total_val: u64,
    delta_val: i64,
    children: BTreeMap<String, TrieBuilder>,
}

impl TrieBuilder {
    fn insert(&mut self, stack: &[String], val: u64) {
        self.total_val = self.total_val.saturating_add(val);
        let Some((head, tail)) = stack.split_first() else {
            self.self_val = self.self_val.saturating_add(val);
            return;
        };
        self.children
            .entry(head.clone())
            .or_default()
            .insert(tail, val);
    }

    fn apply_diff(&mut self, baseline: Option<&TrieBuilder>) {
        let base_tot = baseline.map_or(0, |b| b.total_val);
        self.delta_val = (self.total_val as i64) - (base_tot as i64);
        for (k, child) in &mut self.children {
            let base_child = baseline.and_then(|b| b.children.get(k));
            child.apply_diff(base_child);
        }
    }

    fn finish(self, name: String, base_opt: Option<&TrieBuilder>, differential: bool) -> FlameNode {
        let mut children: Vec<FlameNode> = self
            .children
            .into_iter()
            .map(|(cname, child)| {
                let bchild = base_opt.and_then(|b| b.children.get(&cname));
                child.finish(cname, bchild, differential)
            })
            .collect();
        children.sort_by(|a, b| {
            b.total_value
                .cmp(&a.total_value)
                .then_with(|| a.name.cmp(&b.name))
        });

        let delta_pct = if differential {
            let base_val = base_opt.map_or(0, |b| b.total_val);
            if base_val == 0 {
                if self.total_val > 0 {
                    100.0
                } else {
                    0.0
                }
            } else {
                (self.delta_val as f64) / (base_val as f64) * 100.0
            }
        } else {
            0.0
        };

        FlameNode {
            name,
            self_value: self.self_val,
            total_value: self.total_val,
            delta_value: if differential { self.delta_val } else { 0 },
            delta_pct,
            children,
        }
    }
}

#[must_use]
pub fn build_flamegraph(title: &str, unit: &str, stacks: &[FoldedStack]) -> FlameGraph {
    let mut root = TrieBuilder::default();
    for s in stacks {
        if !s.stack.is_empty() && s.value > 0 {
            root.insert(&s.stack, s.value);
        }
    }
    let total = root.total_val;
    let node = root.finish("root".to_owned(), None, false);
    FlameGraph {
        title: title.to_owned(),
        unit: unit.to_owned(),
        total_value: total,
        differential: false,
        root: node,
    }
}

#[must_use]
pub fn compute_differential_flamegraph(
    title: &str,
    unit: &str,
    baseline_folded: &str,
    regressed_folded: &str,
) -> FlameGraph {
    let mut base_trie = TrieBuilder::default();
    for s in parse_folded(baseline_folded) {
        base_trie.insert(&s.stack, s.value);
    }

    let mut reg_trie = TrieBuilder::default();
    for s in parse_folded(regressed_folded) {
        reg_trie.insert(&s.stack, s.value);
    }

    reg_trie.apply_diff(Some(&base_trie));
    let total = reg_trie.total_val;
    let node = reg_trie.finish("root".to_owned(), Some(&base_trie), true);
    FlameGraph {
        title: title.to_owned(),
        unit: unit.to_owned(),
        total_value: total,
        differential: true,
        root: node,
    }
}

fn max_depth(node: &FlameNode) -> usize {
    1 + node.children.iter().map(max_depth).max().unwrap_or(0)
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn node_color(node: &FlameNode, differential: bool) -> String {
    if !differential {
        // Warm flame palette deterministically keyed by symbol hash
        let h: usize = node
            .name
            .bytes()
            .fold(0usize, |a, b| a.wrapping_mul(31).wrapping_add(b as usize));
        let r = 215 + (h % 40);
        let g = 85 + ((h >> 3) % 120);
        let b = 20 + ((h >> 6) % 45);
        return format!("rgb({r},{g},{b})");
    }
    if node.delta_pct > 2.0 {
        let inten = (node.delta_pct.clamp(0.0, 100.0) / 100.0 * 140.0) as u8;
        let gb = 225u8.saturating_sub(inten);
        format!("rgb(245,{gb},{gb})")
    } else if node.delta_pct < -2.0 {
        let inten = ((-node.delta_pct).clamp(0.0, 100.0) / 100.0 * 140.0) as u8;
        let rb = 225u8.saturating_sub(inten);
        format!("rgb({rb},{rb},245)")
    } else {
        "rgb(225,225,225)".to_owned()
    }
}

/// Render a standalone flamegraph SVG (supports normal & red/blue differential mode).
#[must_use]
pub fn render_svg(fg: &FlameGraph) -> String {
    let width = 1200.0f64;
    let frame_h = 18.0f64;
    let pad = 16.0f64;
    let depth = max_depth(&fg.root);
    let height = (depth as f64) * frame_h + 70.0;
    let total = fg.total_value.max(1) as f64;

    let mut out = String::with_capacity(8192);
    let _ = writeln!(
        out,
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {width} {height}\" width=\"{width}\" height=\"{height}\" style=\"background:#0d1117;font-family:monospace\">"
    );
    let _ = writeln!(
        out,
        "  <text x=\"{w2}\" y=\"24\" text-anchor=\"middle\" fill=\"#e6edf3\" font-size=\"15\" font-weight=\"bold\">{}</text>",
        escape_xml(&fg.title),
        w2 = width / 2.0
    );

    struct DrawRect<'a> {
        node: &'a FlameNode,
        x: f64,
        w: f64,
        level: usize,
    }
    let mut stack = vec![DrawRect {
        node: &fg.root,
        x: pad,
        w: width - 2.0 * pad,
        level: 0,
    }];

    while let Some(item) = stack.pop() {
        if item.w < 0.8 {
            continue;
        }
        let y = height - 24.0 - ((item.level + 1) as f64) * frame_h;
        let color = node_color(item.node, fg.differential);
        let pct = (item.node.total_value as f64) / total * 100.0;
        let title_str = if fg.differential {
            format!(
                "{} ({} {}, {:.2}%, delta {:+.1}%)",
                item.node.name, item.node.total_value, fg.unit, pct, item.node.delta_pct
            )
        } else {
            format!(
                "{} ({} {}, {:.2}%)",
                item.node.name, item.node.total_value, fg.unit, pct
            )
        };
        let _ = writeln!(
            out,
            "  <g><title>{}</title><rect x=\"{:.2}\" y=\"{:.2}\" width=\"{:.2}\" height=\"{:.2}\" fill=\"{color}\" rx=\"2\" stroke=\"#0d1117\" stroke-width=\"0.6\"/>",
            escape_xml(&title_str),
            item.x,
            y,
            item.w,
            frame_h - 1.5
        );
        if item.w > 46.0 {
            let max_chars = ((item.w - 6.0) / 6.8) as usize;
            let label = if item.node.name.len() > max_chars && max_chars >= 4 {
                format!("{}..", &item.node.name[..max_chars - 2])
            } else if max_chars >= 2 {
                item.node.name.clone()
            } else {
                String::new()
            };
            if !label.is_empty() {
                let _ = writeln!(
                    out,
                    "  <text x=\"{:.2}\" y=\"{:.2}\" fill=\"#0d1117\" font-size=\"11\">{}</text>",
                    item.x + 4.0,
                    y + 12.5,
                    escape_xml(&label)
                );
            }
        }
        let _ = writeln!(out, "  </g>");

        let mut cx = item.x;
        for ch in &item.node.children {
            let cw = if item.node.total_value == 0 {
                0.0
            } else {
                item.w * (ch.total_value as f64) / (item.node.total_value as f64)
            };
            stack.push(DrawRect {
                node: ch,
                x: cx,
                w: cw,
                level: item.level + 1,
            });
            cx += cw;
        }
    }

    let _ = writeln!(out, "</svg>");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folded_differential_and_svg_roundtrip() {
        let base = "worker;hot_spin 50\nworker;mutex_wait 20\n";
        let reg = "worker;hot_spin 50\nworker;mutex_wait 90\n";
        let stacks = parse_folded(base);
        assert_eq!(stacks.len(), 2);
        let serialized = to_folded(&stacks);
        assert!(serialized.contains("worker;hot_spin 50"));

        let diff = compute_differential_flamegraph("Off-CPU Diff", "samples", base, reg);
        assert!(diff.differential);
        assert_eq!(diff.total_value, 140);
        let worker = &diff.root.children[0];
        let mutex = worker
            .children
            .iter()
            .find(|n| n.name == "mutex_wait")
            .unwrap();
        assert_eq!(mutex.delta_value, 70);
        assert!(mutex.delta_pct > 300.0);

        let svg = render_svg(&diff);
        assert!(svg.starts_with("<svg"));
        assert!(svg.contains("mutex_wait"));
        assert!(svg.ends_with("</svg>\n"));
    }
}
