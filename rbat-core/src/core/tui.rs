//! # Interactive TUI Dashboard
//!
//! This module implements the ratatui-based Terminal User Interface (TUI) dashboard.
//! It displays a multi-tab view showing general overview metadata, security findings, section entropy, and recommendations.

use super::{AnalysisResult, Confidence, RiskAssessment};
use crossterm::event::{self, Event, KeyCode};
use ratatui::{
    DefaultTerminal, Frame,
    buffer::Buffer,
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Cell, Padding, Gauge, List, ListItem, ListState, Paragraph, Row, Table, TableState,
        Tabs, Widget,
    },
};
use std::io;

/// Tabs representing the different dashboard views.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    /// General summary overview.
    #[default]
    Overview,
    /// Detailed security warnings and indicator matches.
    Security,
    /// Shannon entropy table and layout.
    Entropy,
    /// Threat remediation advice and recommendations.
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

/// The stateful TUI application container.
#[derive(Debug, Default)]
pub struct App {
    analysis_result: AnalysisResult,
    assessment: RiskAssessment,
    current_tab: Tab,
    overview_state: ListState,
    security_state: ListState,
    entropy_state: TableState,
    advice_state: ListState,
}

impl App {
    pub fn new(analysis_result: AnalysisResult, assessment: RiskAssessment) -> Self {
        let mut overview_state = ListState::default();
        overview_state.select(Some(0));
        let mut security_state = ListState::default();
        security_state.select(Some(0));
        let mut entropy_state = TableState::default();
        entropy_state.select(Some(0));
        let mut advice_state = ListState::default();
        advice_state.select(Some(0));

        Self {
            analysis_result,
            assessment,
            current_tab: Tab::Overview,
            overview_state,
            security_state,
            entropy_state,
            advice_state,
        }
    }

    /// runs the application's main loop until the user quits
    pub fn run(&mut self, terminal: &mut DefaultTerminal) -> io::Result<()> {
        loop {
            terminal.draw(|frame| self.draw(frame))?;
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => break Ok(()),
                    KeyCode::Tab | KeyCode::Right => {
                        self.current_tab = self.current_tab.next();
                    }
                    KeyCode::Left => {
                        self.current_tab = self.current_tab.prev();
                    }
                    KeyCode::Down => self.next_item(),
                    KeyCode::Up => self.previous_item(),
                    KeyCode::Char('1') => self.current_tab = Tab::Overview,
                    KeyCode::Char('2') => self.current_tab = Tab::Security,
                    KeyCode::Char('3') => self.current_tab = Tab::Entropy,
                    KeyCode::Char('4') => self.current_tab = Tab::Advice,
                    _ => {}
                }
            }
        }
    }

    fn next_item(&mut self) {
        match self.current_tab {
            Tab::Overview => {
                let i = match self.overview_state.selected() {
                    Some(i) => {
                        if i >= self.assessment.findings.len().saturating_sub(1) {
                            0
                        } else {
                            i + 1
                        }
                    }
                    None => 0,
                };
                self.overview_state.select(Some(i));
            }
            Tab::Security => {
                let total = self.analysis_result.packer_signatures.len()
                    + self.analysis_result.string_values.len()
                    + self.analysis_result.api_hooking.len()
                    + self.analysis_result.process_injection.len();
                let i = match self.security_state.selected() {
                    Some(i) => {
                        if i >= total.saturating_sub(1) {
                            0
                        } else {
                            i + 1
                        }
                    }
                    None => 0,
                };
                self.security_state.select(Some(i));
            }
            Tab::Entropy => {
                let i = match self.entropy_state.selected() {
                    Some(i) => {
                        if i >= self.analysis_result.section_entropy.len().saturating_sub(1) {
                            0
                        } else {
                            i + 1
                        }
                    }
                    None => 0,
                };
                self.entropy_state.select(Some(i));
            }
            Tab::Advice => {
                let i = match self.advice_state.selected() {
                    Some(i) => {
                        if i >= self.assessment.recommendations.len().saturating_sub(1) {
                            0
                        } else {
                            i + 1
                        }
                    }
                    None => 0,
                };
                self.advice_state.select(Some(i));
            }
        }
    }

    fn previous_item(&mut self) {
        match self.current_tab {
            Tab::Overview => {
                let i = match self.overview_state.selected() {
                    Some(i) => {
                        if i == 0 {
                            self.assessment.findings.len().saturating_sub(1)
                        } else {
                            i - 1
                        }
                    }
                    None => 0,
                };
                self.overview_state.select(Some(i));
            }
            Tab::Security => {
                let total = self.analysis_result.packer_signatures.len()
                    + self.analysis_result.string_values.len()
                    + self.analysis_result.api_hooking.len()
                    + self.analysis_result.process_injection.len();
                let i = match self.security_state.selected() {
                    Some(i) => {
                        if i == 0 {
                            total.saturating_sub(1)
                        } else {
                            i - 1
                        }
                    }
                    None => 0,
                };
                self.security_state.select(Some(i));
            }
            Tab::Entropy => {
                let i = match self.entropy_state.selected() {
                    Some(i) => {
                        if i == 0 {
                            self.analysis_result.section_entropy.len().saturating_sub(1)
                        } else {
                            i - 1
                        }
                    }
                    None => 0,
                };
                self.entropy_state.select(Some(i));
            }
            Tab::Advice => {
                let i = match self.advice_state.selected() {
                    Some(i) => {
                        if i == 0 {
                            self.assessment.recommendations.len().saturating_sub(1)
                        } else {
                            i - 1
                        }
                    }
                    None => 0,
                };
                self.advice_state.select(Some(i));
            }
        }
    }

    fn draw(&mut self, frame: &mut Frame) {
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

    fn render_overview(&mut self, area: Rect, buf: &mut Buffer) {
        let chunks = Layout::horizontal([
            Constraint::Percentage(30),
            Constraint::Percentage(35),
            Constraint::Percentage(35),
        ])
        .split(area);

        // Column 1: Target Info & Risk Gauge
        let left_chunks =
            Layout::vertical([Constraint::Length(10), Constraint::Min(0)]).split(chunks[0]);

        let metadata = &self.analysis_result.metadata;
        let info_items = vec![
            ListItem::new(Line::from(vec![
                Span::raw(" TYPE: "),
                Span::styled(&metadata.binary_type, Style::default().fg(Color::Cyan)),
            ])),
            ListItem::new(Line::from(vec![
                Span::raw(" ARCH: "),
                Span::styled(
                    metadata.architecture.to_string(),
                    Style::default().fg(Color::Cyan),
                ),
            ])),
            ListItem::new(Line::from(vec![
                Span::raw(" ENTRY: "),
                Span::styled(
                    format!("0x{:X}", metadata.entry_point),
                    Style::default().fg(Color::Cyan),
                ),
            ])),
        ];

        List::new(info_items)
            .block(Block::bordered().title(" TARGET INFO "))
            .render(left_chunks[0], buf);

        let score = self.assessment.score as f64 / 100.0;
        let gauge_color = if score > 0.75 {
            Color::Red
        } else if score > 0.4 {
            Color::Yellow
        } else {
            Color::Green
        };

        Gauge::default()
            .block(Block::bordered().title(" RISK LEVEL "))
            .gauge_style(Style::default().fg(gauge_color))
            .label(format!(
                "{}% ({})",
                self.assessment.score, self.assessment.severity
            ))
            .ratio(score)
            .render(left_chunks[1], buf);

        // Column 2: Entropy Summary
        let entropy_items: Vec<Row> = self
            .analysis_result
            .section_entropy
            .iter()
            .map(|(name, val)| {
                let color = if *val > 7.0 {
                    Color::Red
                } else if *val > 5.0 {
                    Color::Yellow
                } else {
                    Color::Green
                };
                Row::new(vec![
                    Cell::from(name.as_str()),
                    Cell::from(format!("{:.2}", val)).style(Style::default().fg(color)),
                ])
            })
            .collect();

        Table::new(
            entropy_items,
            [Constraint::Percentage(70), Constraint::Percentage(30)],
        )
        .block(Block::bordered().title(" SECTION ENTROPY "))
        .header(Row::new(vec!["Section", "H"]).style(Style::default().add_modifier(Modifier::BOLD)))
        .render(chunks[1], buf);

        // Column 3: Top Findings
        let findings: Vec<ListItem> = self
            .assessment
            .findings
            .iter()
            .map(|f| {
                let color = match f.confidence {
                    Confidence::Critical => Color::Red,
                    Confidence::High => Color::LightRed,
                    Confidence::Medium => Color::Yellow,
                    Confidence::Low => Color::Green,
                };
                ListItem::new(Line::from(vec![
                    Span::styled(
                        format!("[{:?}] ", f.confidence).to_uppercase(),
                        Style::default().fg(color).add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(&f.indicator),
                ]))
            })
            .collect();

        let list = List::new(findings)
            .block(Block::bordered().title(" TOP FINDINGS (Scrollable) "))
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
            .highlight_symbol(">> ");

        ratatui::widgets::StatefulWidget::render(list, chunks[2], buf, &mut self.overview_state);
    }

    fn render_security(&mut self, area: Rect, buf: &mut Buffer) {
        let mut items = Vec::new();

        // Combine all security findings into one list for unified scrolling
        for (rule, matches) in &self.analysis_result.packer_signatures {
            items.push(ListItem::new(Line::from(vec![
                Span::styled(
                    "PACKER: ",
                    Style::default()
                        .fg(Color::LightRed)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!("{} ({} matches)", rule, matches.len())),
            ])));
        }
        for (rule, matches) in &self.analysis_result.string_values {
            items.push(ListItem::new(Line::from(vec![
                Span::styled(
                    "YARA: ",
                    Style::default()
                        .fg(Color::Magenta)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!("{} ({} matches)", rule, matches.len())),
            ])));
        }
        for (api, addr) in &self.analysis_result.api_hooking {
            items.push(ListItem::new(Line::from(vec![
                Span::styled(
                    "HOOK: ",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(api),
                Span::styled(
                    format!(" @ 0x{:X}", addr),
                    Style::default().fg(Color::DarkGray),
                ),
            ])));
        }
        for func in &self.analysis_result.process_injection {
            items.push(ListItem::new(Line::from(vec![
                Span::styled(
                    "INJECT: ",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
                Span::raw(func),
            ])));
        }

        let list = List::new(items)
            .block(Block::bordered().title(" SECURITY FINDINGS (Scrollable) "))
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
            .highlight_symbol(">> ");

        ratatui::widgets::StatefulWidget::render(list, area, buf, &mut self.security_state);
    }

    fn render_entropy(&mut self, area: Rect, buf: &mut Buffer) {
        let rows: Vec<Row> = self
            .analysis_result
            .section_entropy
            .iter()
            .map(|(name, val)| {
                let status = if *val > 7.5 {
                    "CRITICAL"
                } else if *val > 6.8 {
                    "PACKED?"
                } else if *val > 5.0 {
                    "SUSPICIOUS"
                } else {
                    "NORMAL"
                };
                let color = if *val > 7.0 {
                    Color::Red
                } else if *val > 5.0 {
                    Color::Yellow
                } else {
                    Color::Green
                };

                Row::new(vec![
                    Cell::from(name.as_str()),
                    Cell::from(format!("{:.4}", val)).style(Style::default().fg(color)),
                    Cell::from(status).style(Style::default().fg(color)),
                ])
            })
            .collect();

        let table = Table::new(
            rows,
            [
                Constraint::Percentage(40),
                Constraint::Percentage(30),
                Constraint::Percentage(30),
            ],
        )
        .block(Block::bordered().title(" DETAILED SECTION ENTROPY (Scrollable) "))
        .header(
            Row::new(vec!["Section Name", "Entropy (H)", "Status"])
                .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol(">> ");

        ratatui::widgets::StatefulWidget::render(table, area, buf, &mut self.entropy_state);
    }

    fn render_advice(&mut self, area: Rect, buf: &mut Buffer) {
        let advice_items: Vec<ListItem> = self
            .assessment
            .recommendations
            .iter()
            .map(|r| ListItem::new(format!("• {}", r)).style(Style::default().fg(Color::Green)))
            .collect();

        let list = List::new(advice_items)
            .block(
                Block::bordered()
                    .title(" SECURITY RECOMMENDATIONS (Scrollable) ")
                    .padding(Padding::uniform(1)),
            )
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
            .highlight_symbol(">> ");

        ratatui::widgets::StatefulWidget::render(list, area, buf, &mut self.advice_state);
    }

    fn render_footer(&self, area: Rect, buf: &mut Buffer) {
        let text = " [Q] Quit | [TAB/Arrows] Nav Tabs | [Up/Down] Scroll Content | [1-4] Jump Tab ";
        Paragraph::new(text)
            .style(Style::default().bg(Color::DarkGray).fg(Color::White))
            .alignment(Alignment::Center)
            .render(area, buf);
    }
}

impl Widget for &App {
    fn render(self, _area: Rect, _buf: &mut Buffer) {
        // Compatibility method
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tab_navigation() {
        let tab = Tab::Overview;
        let next = tab.next();
        assert_eq!(next, Tab::Security);
        let prev = next.prev();
        assert_eq!(prev, Tab::Overview);

        assert_eq!(Tab::Advice.next(), Tab::Overview);
        assert_eq!(Tab::Overview.prev(), Tab::Advice);
    }

    #[test]
    fn test_app_initial_state() {
        let app = App::new(AnalysisResult::default(), RiskAssessment::default());
        assert_eq!(app.current_tab, Tab::Overview);
        assert_eq!(app.overview_state.selected(), Some(0));
        assert_eq!(app.security_state.selected(), Some(0));
        assert_eq!(app.entropy_state.selected(), Some(0));
        assert_eq!(app.advice_state.selected(), Some(0));
    }

    #[test]
    fn test_app_next_item_wrap() {
        let mut app = App::new(AnalysisResult::default(), RiskAssessment::default());

        // Overview tab with no findings
        app.next_item();
        assert_eq!(app.overview_state.selected(), Some(0));

        // Switch to Security tab
        app.current_tab = Tab::Security;
        app.next_item();
        assert_eq!(app.security_state.selected(), Some(0));
    }
}
