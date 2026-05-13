use super::{AnalysisResult, Confidence, RiskAssessment};
use crossterm::event::{self, Event, KeyCode};
use ratatui::{
    buffer::Buffer,
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Cell, Gauge, List, ListItem, Padding, Paragraph, Row, Table, Tabs, Widget,
    },
    DefaultTerminal, Frame,
};
use std::io;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    #[default]
    Overview,
    Security,
    Entropy,
    Advice,
}

impl Tab {
    fn next(self) -> Self {
        match self {
            Tab::Overview => Tab::Security,
            Tab::Security => Tab::Entropy,
            Tab::Entropy => Tab::Advice,
            Tab::Advice => Tab::Overview,
        }
    }

    fn prev(self) -> Self {
        match self {
            Tab::Overview => Tab::Advice,
            Tab::Security => Tab::Overview,
            Tab::Entropy => Tab::Security,
            Tab::Advice => Tab::Entropy,
        }
    }

    fn title(self) -> &'static str {
        match self {
            Tab::Overview => " [1] OVERVIEW ",
            Tab::Security => " [2] SECURITY ",
            Tab::Entropy => " [3] ENTROPY ",
            Tab::Advice => " [4] ADVICE ",
        }
    }
}

#[derive(Debug, Default)]
pub struct App {
    analysis_result: AnalysisResult,
    assessment: RiskAssessment,
    current_tab: Tab,
}

impl App {
    pub fn new(analysis_result: AnalysisResult, assessment: RiskAssessment) -> Self {
        Self {
            analysis_result,
            assessment,
            current_tab: Tab::Overview,
        }
    }

    /// runs the application's main loop until the user quits
    pub fn run(&mut self, terminal: &mut DefaultTerminal) -> io::Result<()> {
        loop {
            terminal.draw(|frame| self.draw(frame))?;
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => break Ok(()),
                    KeyCode::Tab | KeyCode::Right => self.current_tab = self.current_tab.next(),
                    KeyCode::Left => self.current_tab = self.current_tab.prev(),
                    KeyCode::Char('1') => self.current_tab = Tab::Overview,
                    KeyCode::Char('2') => self.current_tab = Tab::Security,
                    KeyCode::Char('3') => self.current_tab = Tab::Entropy,
                    KeyCode::Char('4') => self.current_tab = Tab::Advice,
                    _ => {}
                }
            }
        }
    }

    fn draw(&self, frame: &mut Frame) {
        let area = frame.area();
        let chunks = Layout::vertical([
            Constraint::Length(3), // Tabs
            Constraint::Min(0),    // Body
            Constraint::Length(1), // Footer
        ])
        .split(area);

        self.render_tabs(chunks[0], frame.buffer_mut());
        
        match self.current_tab {
            Tab::Overview => self.render_overview(chunks[1], frame.buffer_mut()),
            Tab::Security => self.render_security(chunks[1], frame.buffer_mut()),
            Tab::Entropy => self.render_entropy(chunks[1], frame.buffer_mut()),
            Tab::Advice => self.render_advice(chunks[1], frame.buffer_mut()),
        }

        self.render_footer(chunks[2], frame.buffer_mut());
    }

    fn render_tabs(&self, area: Rect, buf: &mut Buffer) {
        let titles = vec![
            Tab::Overview.title(),
            Tab::Security.title(),
            Tab::Entropy.title(),
            Tab::Advice.title(),
        ];
        
        let highlight_style = Style::default()
            .fg(match self.current_tab {
                Tab::Overview => Color::Cyan,
                Tab::Security => Color::Magenta,
                Tab::Entropy => Color::Yellow,
                Tab::Advice => Color::Green,
            })
            .add_modifier(Modifier::BOLD);

        Tabs::new(titles)
            .block(Block::bordered().title(" RBAT - BINARY ANALYSIS DASHBOARD "))
            .highlight_style(highlight_style)
            .select(self.current_tab as usize)
            .divider("|")
            .render(area, buf);
    }

    fn render_overview(&self, area: Rect, buf: &mut Buffer) {
        let chunks = Layout::horizontal([
            Constraint::Percentage(30),
            Constraint::Percentage(35),
            Constraint::Percentage(35),
        ])
        .split(area);

        // Column 1: Target Info & Risk Gauge
        let left_chunks = Layout::vertical([
            Constraint::Length(10),
            Constraint::Min(0),
        ])
        .split(chunks[0]);

        let metadata = &self.analysis_result.metadata;
        let info_items = vec![
            ListItem::new(Line::from(vec![Span::raw(" TYPE: "), Span::styled(&metadata.binary_type, Style::default().fg(Color::Cyan))])),
            ListItem::new(Line::from(vec![Span::raw(" ARCH: "), Span::styled(metadata.architecture.to_string(), Style::default().fg(Color::Cyan))])),
            ListItem::new(Line::from(vec![Span::raw(" ENTRY: "), Span::styled(format!("0x{:X}", metadata.entry_point), Style::default().fg(Color::Cyan))])),
        ];

        List::new(info_items)
            .block(Block::bordered().title(" TARGET INFO "))
            .render(left_chunks[0], buf);

        let score = self.assessment.score as f64 / 100.0;
        let gauge_color = if score > 0.75 { Color::Red } else if score > 0.4 { Color::Yellow } else { Color::Green };
        
        Gauge::default()
            .block(Block::bordered().title(" RISK LEVEL "))
            .gauge_style(Style::default().fg(gauge_color))
            .label(format!("{}% ({})", self.assessment.score, self.assessment.severity))
            .ratio(score)
            .render(left_chunks[1], buf);

        // Column 2: Entropy Summary
        let entropy_items: Vec<Row> = self.analysis_result.section_entropy.iter()
            .map(|(name, val)| {
                let color = if *val > 7.0 { Color::Red } else if *val > 5.0 { Color::Yellow } else { Color::Green };
                Row::new(vec![
                    Cell::from(name.as_str()),
                    Cell::from(format!("{:.2}", val)).style(Style::default().fg(color)),
                ])
            })
            .collect();

        Table::new(entropy_items, [Constraint::Percentage(70), Constraint::Percentage(30)])
            .block(Block::bordered().title(" SECTION ENTROPY "))
            .header(Row::new(vec!["Section", "H"]).style(Style::default().add_modifier(Modifier::BOLD)))
            .render(chunks[1], buf);

        // Column 3: Top Findings
        let findings: Vec<ListItem> = self.assessment.findings.iter().take(10)
            .map(|f| {
                let color = match f.confidence {
                    Confidence::Critical => Color::Red,
                    Confidence::High => Color::LightRed,
                    Confidence::Medium => Color::Yellow,
                    Confidence::Low => Color::Green,
                };
                ListItem::new(Line::from(vec![
                    Span::styled(format!("[{:?}] ", f.confidence).to_uppercase(), Style::default().fg(color).add_modifier(Modifier::BOLD)),
                    Span::raw(&f.indicator),
                ]))
            })
            .collect();

        List::new(findings)
            .block(Block::bordered().title(" TOP FINDINGS "))
            .render(chunks[2], buf);
    }

    fn render_security(&self, area: Rect, buf: &mut Buffer) {
        let chunks = Layout::vertical([
            Constraint::Percentage(40), // YARA
            Constraint::Percentage(30), // API Hooks
            Constraint::Percentage(30), // Injection
        ])
        .split(area);

        // YARA Matches
        let mut yara_items = Vec::new();
        for (rule, matches) in &self.analysis_result.packer_signatures {
            yara_items.push(ListItem::new(format!("PACKER: {} ({} matches)", rule, matches.len())).style(Style::default().fg(Color::LightRed)));
        }
        for (rule, matches) in &self.analysis_result.string_values {
            yara_items.push(ListItem::new(format!("RULE: {} ({} matches)", rule, matches.len())).style(Style::default().fg(Color::Magenta)));
        }

        List::new(yara_items)
            .block(Block::bordered().title(" YARA MATCHES "))
            .render(chunks[0], buf);

        // API Hooks
        let api_items: Vec<ListItem> = self.analysis_result.api_hooking.iter()
            .map(|(api, addr)| {
                ListItem::new(Line::from(vec![
                    Span::styled("HOOK: ", Style::default().fg(Color::Yellow)),
                    Span::raw(api),
                    Span::styled(format!(" @ 0x{:X}", addr), Style::default().fg(Color::DarkGray)),
                ]))
            })
            .collect();

        List::new(api_items)
            .block(Block::bordered().title(" API HOOKING INDICATORS "))
            .render(chunks[1], buf);

        // Injection
        let inj_items: Vec<ListItem> = self.analysis_result.process_injection.iter()
            .map(|f| ListItem::new(format!("SUSPICIOUS IMPORT: {}", f)).style(Style::default().fg(Color::Red)))
            .collect();

        List::new(inj_items)
            .block(Block::bordered().title(" PROCESS INJECTION PATTERNS "))
            .render(chunks[2], buf);
    }

    fn render_entropy(&self, area: Rect, buf: &mut Buffer) {
        let rows: Vec<Row> = self.analysis_result.section_entropy.iter()
            .map(|(name, val)| {
                let status = if *val > 7.5 { "CRITICAL" } else if *val > 6.8 { "PACKED?" } else if *val > 5.0 { "SUSPICIOUS" } else { "NORMAL" };
                let color = if *val > 7.0 { Color::Red } else if *val > 5.0 { Color::Yellow } else { Color::Green };
                
                Row::new(vec![
                    Cell::from(name.as_str()),
                    Cell::from(format!("{:.4}", val)).style(Style::default().fg(color)),
                    Cell::from(status).style(Style::default().fg(color)),
                ])
            })
            .collect();

        Table::new(rows, [Constraint::Percentage(40), Constraint::Percentage(30), Constraint::Percentage(30)])
            .block(Block::bordered().title(" DETAILED SECTION ENTROPY "))
            .header(Row::new(vec!["Section Name", "Entropy (H)", "Status"]).style(Style::default().add_modifier(Modifier::BOLD)))
            .render(area, buf);
    }

    fn render_advice(&self, area: Rect, buf: &mut Buffer) {
        let advice_items: Vec<ListItem> = self.assessment.recommendations.iter()
            .map(|r| ListItem::new(format!("• {}", r)).style(Style::default().fg(Color::Green)))
            .collect();

        List::new(advice_items)
            .block(Block::bordered().title(" SECURITY RECOMMENDATIONS ").padding(Padding::uniform(1)))
            .render(area, buf);
    }

    fn render_footer(&self, area: Rect, buf: &mut Buffer) {
        let text = " [Q] Quit | [TAB] Next Tab | [1-4] Switch Tab | [Arrows] Navigate ";
        Paragraph::new(text)
            .style(Style::default().bg(Color::DarkGray).fg(Color::White))
            .alignment(Alignment::Center)
            .render(area, buf);
    }
}

impl Widget for &App {
    fn render(self, _area: Rect, _buf: &mut Buffer) {
        // We handle rendering inside App::draw directly to have access to Frame
        // but this is kept for compatibility if needed.
    }
}
