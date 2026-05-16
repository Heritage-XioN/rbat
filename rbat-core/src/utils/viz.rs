use std::collections::HashMap;

/// Generates an HTML heatmap string from section entropy data.
/// Each section is rendered as a colored cell where the color intensity
/// represents the entropy value (0.0=blue/cool to 8.0=red/hot).
/// Uses HTML Tables for maximum compatibility with the PDF engine's background rendering.
pub fn generate_entropy_heatmap_svg(data: &HashMap<String, f64>) -> String {
    let mut sections: Vec<(String, f64)> = data.iter().map(|(k, v)| (k.clone(), *v)).collect();
    sections.sort_by(|a, b| a.0.cmp(&b.0));

    if sections.is_empty() {
        return String::from(
            "<p style='color: #666; text-align: center;'>No section data available</p>",
        );
    }

    let mut html = String::from(
        "<table style=\"width: 100%; border-collapse: separate; border-spacing: 10px; margin: 0 auto;\">",
    );

    // Draw each section cell in rows of 6
    for chunk in sections.chunks(6) {
        html.push_str("<tr>");
        for (name, entropy) in chunk {
            let normalized = (entropy / 8.0).clamp(0.0, 1.0);
            let color_hex = entropy_to_hex(normalized);
            let text_color = if normalized > 0.6 {
                "#ffffff"
            } else {
                "#000000"
            };

            html.push_str(&format!(
                "<td style=\"background-color: {} !important; width: 16%; padding: 15px 5px; border: 1px solid #dddddd; border-radius: 4px; text-align: center; vertical-align: middle;\">
                    <div style=\"color: {} !important; font-weight: bold; font-size: 14px; margin-bottom: 5px;\">{:.2}</div>
                    <div style=\"color: #333333; font-size: 9px; word-break: break-all; line-height: 1.1;\">{}</div>
                </td>",
                color_hex, text_color, entropy, name
            ));
        }

        // Fill remaining cells in the row if necessary
        if chunk.len() < 6 {
            for _ in 0..(6 - chunk.len()) {
                html.push_str("<td style=\"width: 16%;\"></td>");
            }
        }
        html.push_str("</tr>");
    }
    html.push_str("</table>");

    // Legend
    html.push_str("<div style=\"margin-top: 30px; text-align: center;\">");
    html.push_str("<table style=\"margin: 0 auto; border-collapse: collapse;\"><tr>");

    let num_stops = 20;
    for i in 0..num_stops {
        let normalized = i as f64 / num_stops as f64;
        let color_hex = entropy_to_hex(normalized);
        html.push_str(&format!(
            "<td style=\"width: 15px; height: 12px; background-color: {} !important; padding: 0;\"></td>",
            color_hex
        ));
    }

    html.push_str("</tr></table>");

    html.push_str("<div style=\"width: 300px; margin: 5px auto 0; font-size: 10px; color: #666666; display: flex; justify-content: space-between;\">
        <span>0.0 (Low)</span>
        <span style=\"margin-left: 190px;\">8.0 (High)</span>
    </div>");

    html.push_str("<div style=\"font-size: 10px; color: #999999; margin-top: 10px;\">Entropy Heatmap: Packed or encrypted data spikes toward 8.0</div>");
    html.push_str("</div>");

    html
}

/// Maps a normalized entropy value (0.0 to 1.0) to a hex color string.
/// Low entropy = blue/green (cool), High entropy = red (hot).
fn entropy_to_hex(normalized: f64) -> String {
    let (r, g, b) = if normalized < 0.25 {
        // Blue -> Cyan
        let t = normalized / 0.25;
        (0, (t * 200.0) as u8, 200)
    } else if normalized < 0.5 {
        // Cyan -> Green/Yellow
        let t = (normalized - 0.25) / 0.25;
        (0, 200, (200.0 * (1.0 - t)) as u8)
    } else if normalized < 0.75 {
        // Green/Yellow -> Orange
        let t = (normalized - 0.5) / 0.25;
        ((t * 255.0) as u8, (200.0 - t * 100.0) as u8, 0)
    } else {
        // Orange -> Red
        let t = (normalized - 0.75) / 0.25;
        (255, (100.0 * (1.0 - t)) as u8, 0)
    };
    format!("#{:02x}{:02x}{:02x}", r, g, b)
}
