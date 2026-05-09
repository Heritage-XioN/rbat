use std::collections::HashMap;

/// Generates an SVG heatmap string from section entropy data.
/// Each section is rendered as a colored cell where the color intensity
/// represents the entropy value (0.0=blue/cool to 8.0=red/hot).
pub fn generate_entropy_heatmap_svg(data: &HashMap<String, f64>) -> String {
    let mut sections: Vec<(String, f64)> = data.iter().map(|(k, v)| (k.clone(), *v)).collect();
    sections.sort_by(|a, b| a.0.cmp(&b.0));

    if sections.is_empty() {
        return String::from("<svg xmlns='http://www.w3.org/2000/svg' width='400' height='100'><text x='200' y='50' text-anchor='middle' fill='#666'>No section data available</text></svg>");
    }

    let cell_width = 100;
    let cell_height = 60;
    let label_height = 30;
    let value_height = 25;
    let legend_height = 50;
    let padding = 20;
    let total_width = sections.len() * cell_width + padding * 2;
    let total_height = cell_height + label_height + value_height + legend_height + padding * 2;

    let mut svg = format!(
        "<svg xmlns='http://www.w3.org/2000/svg' width='{}' height='{}' style='font-family: Arial, sans-serif;'>",
        total_width, total_height
    );

    // Background
    svg.push_str(&format!(
        "<rect width='{}' height='{}' fill='#ffffff'/>",
        total_width, total_height
    ));

    // Draw each section cell
    for (i, (name, entropy)) in sections.iter().enumerate() {
        let x = padding + i * cell_width;
        let y = padding;
        let normalized = (entropy / 8.0).clamp(0.0, 1.0);
        let (r, g, b) = entropy_to_rgb(normalized);
        let text_color = if normalized > 0.6 { "white" } else { "#333" };

        // Cell rectangle
        svg.push_str(&format!(
            "<rect x='{}' y='{}' width='{}' height='{}' fill='rgb({},{},{})' stroke='#ccc' stroke-width='1'/>",
            x, y, cell_width, cell_height, r, g, b
        ));

        // Entropy value inside cell
        svg.push_str(&format!(
            "<text x='{}' y='{}' text-anchor='middle' fill='{}' font-size='14' font-weight='bold'>{:.2}</text>",
            x + cell_width / 2,
            y + cell_height / 2 + 5,
            text_color,
            entropy
        ));

        // Section name below cell
        svg.push_str(&format!(
            "<text x='{}' y='{}' text-anchor='middle' fill='#333' font-size='11'>{}</text>",
            x + cell_width / 2,
            y + cell_height + 18,
            name
        ));
    }

    // Legend bar
    let legend_y = padding + cell_height + label_height + value_height;
    let legend_width = total_width - padding * 2;
    let num_stops = 20;
    let stop_width = legend_width / num_stops;
    for i in 0..num_stops {
        let normalized = i as f64 / num_stops as f64;
        let (r, g, b) = entropy_to_rgb(normalized);
        svg.push_str(&format!(
            "<rect x='{}' y='{}' width='{}' height='15' fill='rgb({},{},{})'/>",
            padding + i * stop_width,
            legend_y,
            stop_width + 1,
            r, g, b
        ));
    }
    // Legend labels
    svg.push_str(&format!(
        "<text x='{}' y='{}' fill='#666' font-size='10'>0.0 (Low)</text>",
        padding,
        legend_y + 28
    ));
    svg.push_str(&format!(
        "<text x='{}' y='{}' text-anchor='end' fill='#666' font-size='10'>8.0 (High)</text>",
        padding + legend_width,
        legend_y + 28
    ));
    svg.push_str(&format!(
        "<text x='{}' y='{}' text-anchor='middle' fill='#888' font-size='10'>Warning: Spikes near 8.0 denote heavily packed/encrypted sections</text>",
        total_width / 2,
        legend_y + 42
    ));

    svg.push_str("</svg>");
    svg
}

/// Maps a normalized entropy value (0.0 to 1.0) to an RGB color.
/// Low entropy = blue/green (cool), High entropy = red (hot).
fn entropy_to_rgb(normalized: f64) -> (u8, u8, u8) {
    if normalized < 0.25 {
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
    }
}
