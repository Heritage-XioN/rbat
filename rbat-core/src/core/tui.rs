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
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Cell, Gauge, List, ListItem, ListState, Padding, Paragraph, Row, Table, TableState,
        Tabs, Widget,
    },
};
use std::io;

// ── RBAT Design System Palette ───
// Matched to the Next.js client CSS variables for visual consistency.
#[allow(dead_code)]
mod palette {
    use ratatui::style::Color;

    // Surfaces & borders
    pub const BG: Color = Color::Rgb(10, 12, 26); // --rbat-bg        #0a0c1a
    pub const CARD: Color = Color::Rgb(17, 19, 39); // --rbat-card       #111327
    pub const SURFACE: Color = Color::Rgb(26, 29, 53); // --secondary       #1a1d35
    pub const BORDER: Color = Color::Rgb(30, 32, 64); // --rbat-border     #1e2040

    // Text hierarchy
    pub const TEXT: Color = Color::Rgb(240, 240, 245); // --rbat-text       #f0f0f5
    pub const TEXT_SECONDARY: Color = Color::Rgb(156, 163, 175); // --rbat-text-secondary #9ca3af
    pub const MUTED: Color = Color::Rgb(107, 114, 128); // --rbat-muted      #6b7280

    // Accent (purple gradient)
    pub const ACCENT: Color = Color::Rgb(192, 132, 252); // --rbat-accent     #c084fc
    pub const ACCENT_DIM: Color = Color::Rgb(168, 85, 247); // chart-2 / purple-500 #a855f7
    pub const PINK: Color = Color::Rgb(244, 114, 182); // gradient endpoint #f472b6

    // Status / severity
    pub const DANGER: Color = Color::Rgb(239, 68, 68); // --rbat-high       #ef4444
    pub const DANGER_LIGHT: Color = Color::Rgb(248, 113, 113); // red-400          #f87171
    pub const WARNING: Color = Color::Rgb(245, 158, 11); // --rbat-medium     #f59e0b
    pub const WARNING_LIGHT: Color = Color::Rgb(251, 191, 36); // amber-400       #fbbf24
    pub const SUCCESS: Color = Color::Rgb(34, 197, 94); // --rbat-low        #22c55e
    pub const SUCCESS_LIGHT: Color = Color::Rgb(74, 222, 128); // green-400       #4ade80
}

/// Tabs representing the different dashboard views.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    /// General summary overview.
    #[default]
    Overview = 0,
    /// Detailed security warnings and indicator matches.
    Security = 1,
    /// Interactive Control Flow disassembly view.
    Disassembly = 2,
    /// Shannon entropy table and layout.
    Entropy = 3,
    /// Threat remediation advice and recommendations.
    Advice = 4,
}

impl Tab {
    fn next(self) -> Self {
        match self {
            Tab::Overview => Tab::Security,
            Tab::Security => Tab::Disassembly,
            Tab::Disassembly => Tab::Entropy,
            Tab::Entropy => Tab::Advice,
            Tab::Advice => Tab::Overview,
        }
    }

    fn prev(self) -> Self {
        match self {
            Tab::Overview => Tab::Advice,
            Tab::Security => Tab::Overview,
            Tab::Disassembly => Tab::Security,
            Tab::Entropy => Tab::Disassembly,
            Tab::Advice => Tab::Entropy,
        }
    }

    fn title(self) -> &'static str {
        match self {
            Tab::Overview => " [1] OVERVIEW ",
            Tab::Security => " [2] SECURITY ",
            Tab::Disassembly => " [3] DISASSEMBLY ",
            Tab::Entropy => " [4] ENTROPY ",
            Tab::Advice => " [5] ADVICE ",
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
    disasm_state: ListState,
    instr_state: TableState,
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
        let mut disasm_state = ListState::default();
        disasm_state.select(Some(0));
        let mut instr_state = TableState::default();
        instr_state.select(Some(0));

        Self {
            analysis_result,
            assessment,
            current_tab: Tab::Overview,
            overview_state,
            security_state,
            entropy_state,
            advice_state,
            disasm_state,
            instr_state,
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
                    KeyCode::Char('s') => {
                        if self.current_tab == Tab::Disassembly {
                            self.next_instruction();
                        }
                    }
                    KeyCode::Char('w') => {
                        if self.current_tab == Tab::Disassembly {
                            self.prev_instruction();
                        }
                    }
                    KeyCode::Char('1') => self.current_tab = Tab::Overview,
                    KeyCode::Char('2') => self.current_tab = Tab::Security,
                    KeyCode::Char('3') => self.current_tab = Tab::Disassembly,
                    KeyCode::Char('4') => self.current_tab = Tab::Entropy,
                    KeyCode::Char('5') => self.current_tab = Tab::Advice,
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
            Tab::Disassembly => {
                let total = self
                    .analysis_result
                    .cfg
                    .as_ref()
                    .map(|c| c.blocks.len())
                    .unwrap_or(0);
                let i = match self.disasm_state.selected() {
                    Some(i) => {
                        if i >= total.saturating_sub(1) {
                            0
                        } else {
                            i + 1
                        }
                    }
                    None => 0,
                };
                self.disasm_state.select(Some(i));
                // reset instruction scroll when changing blocks
                self.instr_state.select(Some(0));
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
            Tab::Disassembly => {
                let total = self
                    .analysis_result
                    .cfg
                    .as_ref()
                    .map(|c| c.blocks.len())
                    .unwrap_or(0);
                let i = match self.disasm_state.selected() {
                    Some(i) => {
                        if i == 0 {
                            total.saturating_sub(1)
                        } else {
                            i - 1
                        }
                    }
                    None => 0,
                };
                self.disasm_state.select(Some(i));
                // reset instruction scroll when changing blocks
                self.instr_state.select(Some(0));
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

    fn next_instruction(&mut self) {
        let total = self.get_selected_block_instructions_count();
        let i = match self.instr_state.selected() {
            Some(i) => {
                if i >= total.saturating_sub(1) {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.instr_state.select(Some(i));
    }

    fn prev_instruction(&mut self) {
        let total = self.get_selected_block_instructions_count();
        let i = match self.instr_state.selected() {
            Some(i) => {
                if i == 0 {
                    total.saturating_sub(1)
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.instr_state.select(Some(i));
    }

    fn get_selected_block_instructions_count(&self) -> usize {
        let blocks: Vec<&crate::core::types::BasicBlock> =
            if let Some(ref cfg) = self.analysis_result.cfg {
                let mut v: Vec<&crate::core::types::BasicBlock> = cfg.blocks.values().collect();
                v.sort_by_key(|b| b.start_address);
                v
            } else {
                vec![]
            };
        if let Some(block) = self.disasm_state.selected().and_then(|idx| blocks.get(idx)) {
            return block.instructions.len();
        }
        0
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
            Tab::Disassembly => self.render_disassembly(chunks[1], frame.buffer_mut()),
            Tab::Entropy => self.render_entropy(chunks[1], frame.buffer_mut()),
            Tab::Advice => self.render_advice(chunks[1], frame.buffer_mut()),
        }

        self.render_footer(chunks[2], frame.buffer_mut());
    }

    fn render_tabs(&self, area: Rect, buf: &mut Buffer) {
        let titles = vec![
            Tab::Overview.title(),
            Tab::Security.title(),
            Tab::Disassembly.title(),
            Tab::Entropy.title(),
            Tab::Advice.title(),
        ];

        let highlight_style = Style::default()
            .fg(match self.current_tab {
                Tab::Overview => palette::ACCENT,
                Tab::Security => palette::PINK,
                Tab::Disassembly => palette::ACCENT_DIM,
                Tab::Entropy => palette::WARNING_LIGHT,
                Tab::Advice => palette::SUCCESS_LIGHT,
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
                Span::styled(&metadata.binary_type, Style::default().fg(palette::ACCENT)),
            ])),
            ListItem::new(Line::from(vec![
                Span::raw(" ARCH: "),
                Span::styled(
                    metadata.architecture_name(),
                    Style::default().fg(palette::ACCENT),
                ),
            ])),
            ListItem::new(Line::from(vec![
                Span::raw(" ENTRY: "),
                Span::styled(
                    format!("0x{:X}", metadata.entry_point),
                    Style::default().fg(palette::ACCENT),
                ),
            ])),
        ];

        List::new(info_items)
            .block(Block::bordered().title(" TARGET INFO "))
            .render(left_chunks[0], buf);

        let score = self.assessment.score as f64 / 100.0;
        let gauge_color = if score > 0.75 {
            palette::DANGER
        } else if score > 0.4 {
            palette::WARNING
        } else {
            palette::SUCCESS
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
                    palette::DANGER
                } else if *val > 5.0 {
                    palette::WARNING
                } else {
                    palette::SUCCESS
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
                    Confidence::Critical => palette::DANGER,
                    Confidence::High => palette::DANGER_LIGHT,
                    Confidence::Medium => palette::WARNING_LIGHT,
                    Confidence::Low => palette::SUCCESS_LIGHT,
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
                        .fg(palette::DANGER_LIGHT)
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
                        .fg(palette::ACCENT_DIM)
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
                        .fg(palette::WARNING_LIGHT)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(api),
                Span::styled(
                    format!(" @ 0x{:X}", addr),
                    Style::default().fg(palette::MUTED),
                ),
            ])));
        }
        for func in &self.analysis_result.process_injection {
            items.push(ListItem::new(Line::from(vec![
                Span::styled(
                    "INJECT: ",
                    Style::default()
                        .fg(palette::DANGER)
                        .add_modifier(Modifier::BOLD),
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

    fn render_disassembly(&mut self, area: Rect, buf: &mut Buffer) {
        let chunks = Layout::horizontal([Constraint::Percentage(35), Constraint::Percentage(65)])
            .split(area);

        // Sort blocks by start address
        let blocks: Vec<&crate::core::types::BasicBlock> =
            if let Some(ref cfg) = self.analysis_result.cfg {
                let mut v: Vec<&crate::core::types::BasicBlock> = cfg.blocks.values().collect();
                v.sort_by_key(|b| b.start_address);
                v
            } else {
                vec![]
            };

        // Render basic blocks list
        let block_items: Vec<ListItem> = blocks
            .iter()
            .map(|b| {
                ListItem::new(Line::from(vec![
                    Span::styled(
                        "BLOCK: ",
                        Style::default()
                            .fg(palette::ACCENT)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(format!("0x{:X} - 0x{:X}", b.start_address, b.end_address)),
                ]))
            })
            .collect();

        let block_list = List::new(block_items)
            .block(Block::bordered().title(" BASIC BLOCKS (Scroll: Up/Down) "))
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
            .highlight_symbol(">> ");

        ratatui::widgets::StatefulWidget::render(
            block_list,
            chunks[0],
            buf,
            &mut self.disasm_state,
        );

        // Render instructions table of the selected basic block
        let selected_idx = self.disasm_state.selected();
        let selected_block = selected_idx.and_then(|idx| blocks.get(idx));

        if let Some(block) = selected_block {
            let rows: Vec<Row> = block
                .instructions
                .iter()
                .map(|inst| {
                    Row::new(vec![
                        Cell::from(format!("0x{:08X}", inst.address))
                            .style(Style::default().fg(palette::MUTED)),
                        Cell::from(inst.mnemonic.as_str()).style(
                            Style::default()
                                .fg(palette::ACCENT)
                                .add_modifier(Modifier::BOLD),
                        ),
                        Cell::from(inst.op_str.as_str()).style(Style::default().fg(palette::TEXT)),
                    ])
                })
                .collect();

            let table = Table::new(
                rows,
                [
                    Constraint::Percentage(30),
                    Constraint::Percentage(20),
                    Constraint::Percentage(50),
                ],
            )
            .block(Block::bordered().title(" INSTRUCTIONS (Scroll: W/S) "))
            .header(
                Row::new(vec!["Address", "Mnemonic", "Operands"])
                    .style(Style::default().add_modifier(Modifier::BOLD)),
            )
            .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED))
            .highlight_symbol(">> ");

            ratatui::widgets::StatefulWidget::render(table, chunks[1], buf, &mut self.instr_state);
        } else {
            Paragraph::new("No basic blocks parsed or selected.")
                .block(Block::bordered().title(" INSTRUCTIONS "))
                .render(chunks[1], buf);
        }
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
                    palette::DANGER
                } else if *val > 5.0 {
                    palette::WARNING
                } else {
                    palette::SUCCESS
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
            .map(|r| {
                ListItem::new(format!("• {}", r)).style(Style::default().fg(palette::SUCCESS_LIGHT))
            })
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
        let text = " [Q] Quit | [TAB/Arrows] Nav Tabs | [Up/Down] Scroll Blocks | [W/S] Scroll Instr | [1-5] Jump Tab ";
        Paragraph::new(text)
            .style(
                Style::default()
                    .bg(palette::SURFACE)
                    .fg(palette::TEXT_SECONDARY),
            )
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

        assert_eq!(Tab::Security.next(), Tab::Disassembly);
        assert_eq!(Tab::Disassembly.next(), Tab::Entropy);
        assert_eq!(Tab::Entropy.next(), Tab::Advice);
        assert_eq!(Tab::Advice.next(), Tab::Overview);

        assert_eq!(Tab::Overview.prev(), Tab::Advice);
        assert_eq!(Tab::Disassembly.prev(), Tab::Security);
        assert_eq!(Tab::Entropy.prev(), Tab::Disassembly);
    }

    #[test]
    fn test_app_initial_state() {
        let app = App::new(AnalysisResult::default(), RiskAssessment::default());
        assert_eq!(app.current_tab, Tab::Overview);
        assert_eq!(app.overview_state.selected(), Some(0));
        assert_eq!(app.security_state.selected(), Some(0));
        assert_eq!(app.entropy_state.selected(), Some(0));
        assert_eq!(app.advice_state.selected(), Some(0));
        assert_eq!(app.disasm_state.selected(), Some(0));
        assert_eq!(app.instr_state.selected(), Some(0));
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

    #[test]
    fn test_disassembly_scrolling() {
        let mut app = App::new(AnalysisResult::default(), RiskAssessment::default());
        app.current_tab = Tab::Disassembly;

        // No basic blocks initially
        app.next_item();
        assert_eq!(app.disasm_state.selected(), Some(0));
        app.previous_item();
        assert_eq!(app.disasm_state.selected(), Some(0));

        // No instructions initially
        app.next_instruction();
        assert_eq!(app.instr_state.selected(), Some(0));
        app.prev_instruction();
        assert_eq!(app.instr_state.selected(), Some(0));
    }
}
