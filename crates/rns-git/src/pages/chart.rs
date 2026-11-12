//! The stats page charts (`render_chart_halfblock`, `render_combined_chart`, `pages.py`).

use super::{CLR_DIM, RCLR_DOWNLOAD, RCLR_FETCH, RCLR_PUSH, RCLR_VIEW};

fn expand(c: &str) -> String {
    if c.chars().count() == 3 {
        c.chars().flat_map(|ch| [ch, ch]).collect()
    } else {
        c.chars().take(6).collect()
    }
}

fn rgb(h: &str) -> [f64; 3] {
    let part = |i: usize| f64::from(u8::from_str_radix(&h[i..i + 2], 16).unwrap_or(0));
    [part(0), part(2), part(4)]
}

/// `int(g + (c - g) * min(1, t * f))` per channel, as two hex digits each.
fn blend(c: [f64; 3], g: [f64; 3], t: f64, f: f64) -> String {
    let m = (t * f).min(1.0);
    (0..3)
        .map(|i| format!("{:02x}", (g[i] + (c[i] - g[i]) * m) as i64))
        .collect()
}

fn pad_left(s: &str, width: usize) -> String {
    let n = s.chars().count();
    format!("{s}{}", " ".repeat(width.saturating_sub(n)))
}

fn pad_right(s: &str, width: usize) -> String {
    let n = s.chars().count();
    format!("{}{s}", " ".repeat(width.saturating_sub(n)))
}

fn first12(s: &str) -> String {
    s.chars().take(12).collect()
}

/// `render_chart` (the half-block renderer, height 10).
pub fn render_chart(
    data: &[i64],
    labels: &[String],
    color: &str,
    secondary_color: Option<&str>,
    gradient_factor: Option<f64>,
) -> String {
    let height = 10i64;
    let gradient_factor = gradient_factor.filter(|g| *g != 0.0).unwrap_or(1.3);
    if data.iter().all(|d| *d == 0) {
        return "No data available\n".to_string();
    }
    let max_val = (*data.iter().max().unwrap_or(&1)).max(1) as f64;
    let max_label = *data.iter().max().unwrap_or(&1);
    let primary = expand(color);
    let secondary = match secondary_color {
        Some(c) => expand(c),
        None => (0..3)
            .map(|i| {
                let v = i64::from_str_radix(&primary[i * 2..i * 2 + 2], 16).unwrap_or(0);
                format!("{:02x}", (v as f64 * 0.42) as i64)
            })
            .collect(),
    };
    let (p, s) = (rgb(&primary), rgb(&secondary));
    let gradient = |t: f64| blend(p, s, t, gradient_factor);
    let mut out = format!("`FT{primary}Peak: {max_label}`f\n");
    for row in (1..=height).rev() {
        let h = height as f64;
        let r = row as f64;
        let row_top = (r / h) * max_val;
        let row_bottom = ((r - 1.0) / h) * max_val;
        let row_mid = (row_top + row_bottom) / 2.0;
        let grad_top = r / h;
        let grad_mid = (r - 0.5) / h;
        let mut line = String::from("│");
        for &val in data {
            let v = val as f64;
            let upper = v >= row_top;
            let lower = v >= row_mid || (row == 1 && val > 0);
            if !upper && !lower {
                line.push(' ');
            } else if upper {
                line.push_str(&format!(
                    "`FT{}`BT{}▀`f`b",
                    gradient(grad_top),
                    gradient(grad_mid)
                ));
            } else {
                line.push_str(&format!("`FT{}▄`f", gradient(grad_mid)));
            }
        }
        out.push_str(&line);
        out.push('\n');
    }
    let bottom = format!("└{}┘", "─".repeat(data.len()));
    out.push_str(&bottom);
    out.push('\n');
    let width = data.len() as i64 + 2;
    let first = pad_left(&first12(&labels[0]), 12);
    let last = pad_right(&first12(&labels[labels.len() - 1]), 12);
    let middle = (width - first.chars().count() as i64 - last.chars().count() as i64).max(0);
    out.push_str(&format!(
        "{CLR_DIM}{first}`f{}{CLR_DIM}{last}`f\n",
        " ".repeat(middle as usize)
    ));
    out
}

/// `render_combined_chart` with its default height 6 and dim 0.87.
pub fn render_combined_chart(
    views: &[i64],
    fetches: &[i64],
    pushes: &[i64],
    downloads: &[i64],
    labels: &[String],
) -> String {
    let height = 6i64;
    let dim = 0.87;
    if views.is_empty() || fetches.is_empty() || pushes.is_empty() || downloads.is_empty() {
        return "No data available\n".to_string();
    }
    let color = |c: &str| blend(rgb(&expand(c)), [0.0; 3], dim, 1.0);
    let categories = ["pushes", "fetches", "views", "downloads"];
    let colors = [
        color(RCLR_PUSH),
        color(RCLR_FETCH),
        color(RCLR_VIEW),
        color(RCLR_DOWNLOAD),
    ];
    let series = [pushes, fetches, views, downloads];
    let legend: Vec<String> = categories
        .iter()
        .zip(&colors)
        .map(|(cat, col)| {
            let mut name = cat.to_string();
            name[..1].make_ascii_uppercase();
            format!("`FT{col}`BT{col}██`f`b {name}")
        })
        .collect();
    let mut out = format!("{}\n\n", legend.join("  "));
    let n = views.len();
    for row in (1..=height).rev() {
        let (h, r) = (height as f64, row as f64);
        let (lower_min, lower_max) = ((r - 1.0) / h, (r - 0.5) / h);
        let (upper_min, upper_max) = ((r - 0.5) / h, r / h);
        let mut line = String::from("│");
        for i in 0..n {
            let total: i64 = series.iter().map(|d| d[i]).sum();
            if total == 0 {
                line.push(' ');
                continue;
            }
            let mut cumsum = 0i64;
            let mut ranges = [(0.0f64, 0.0f64); 4];
            for (k, d) in series.iter().enumerate() {
                let start = cumsum as f64 / total as f64;
                cumsum += d[i];
                ranges[k] = (start, cumsum as f64 / total as f64);
            }
            let pixel =
                |pmin: f64, pmax: f64| (0..4).find(|&k| pmin < ranges[k].1 && pmax > ranges[k].0);
            match (pixel(upper_min, upper_max), pixel(lower_min, lower_max)) {
                (None, None) => line.push(' '),
                (Some(u), Some(l)) if u == l => {
                    line.push_str(&format!("`FT{0}`BT{0}█`f`b", colors[u]));
                }
                (Some(u), Some(l)) => {
                    line.push_str(&format!("`FT{}`BT{}▀`f`b", colors[u], colors[l]));
                }
                (Some(u), None) => line.push_str(&format!("`FT{}▀`f", colors[u])),
                (None, Some(l)) => line.push_str(&format!("`FT{}▄`f", colors[l])),
            }
        }
        out.push_str(&line);
        out.push('\n');
    }
    let bottom = format!("└{}┘", "─".repeat(n));
    out.push_str(&bottom);
    out.push('\n');
    if !labels.is_empty() {
        let first = first12(&labels[0]);
        let last = first12(&labels[labels.len() - 1]);
        let mid =
            (n as i64 + 2 - first.chars().count() as i64 - last.chars().count() as i64).max(0);
        out.push_str(&format!(
            "{CLR_DIM}{first}{}{last}`f\n",
            " ".repeat(mid as usize)
        ));
    }
    out
}
