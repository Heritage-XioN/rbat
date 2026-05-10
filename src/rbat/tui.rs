use super::{AnalysisResult, RiskAssessment};
use crossterm::event::{self, Event, KeyCode};
use ratatui::{
    DefaultTerminal, Frame,
    buffer::Buffer,
    layout::{Constraint, Layout, Rect},
    style::{Color, Stylize},
    text::ToSpan,
    widgets::{Block, List, ListItem, Widget},
};
use std::io;

#[derive(Debug, Default)]
pub struct App {
    analysis_result: AnalysisResult,
    assessment: RiskAssessment,
}

impl App {
    pub fn new(analysis_result: AnalysisResult, assessment: RiskAssessment) -> Self {
        Self {
            analysis_result,
            assessment,
        }
    }

    /// runs the application's main loop until the user quits
    pub fn run(&mut self, terminal: &mut DefaultTerminal) -> io::Result<()> {
        loop {
            terminal.draw(|frame| self.draw(frame))?;
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => break Ok(()),
                    _ => {}
                }
            }
        }
    }

    fn draw(&self, frame: &mut Frame) {
        frame.render_widget(self, frame.area());
    }
}

impl Widget for &App {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let binary_type = format!(
            " BINARY TYPE: {} ",
            self.analysis_result.metadata.binary_type
        );
        let entry_point = format!(
            " ENTRY POINT: {} (0x{:X}) ",
            self.analysis_result.metadata.entry_point, self.analysis_result.metadata.entry_point
        );
        let architecture = format!(
            " ARCHITECTURE: {} ",
            self.analysis_result.metadata.architecture
        );

        let container = Layout::vertical([
            Constraint::Percentage(70),
            Constraint::Percentage(30), // Body
        ])
        .split(area);

        let top_layout = Layout::horizontal([
            Constraint::Fill(1),
            Constraint::Fill(1),
            Constraint::Fill(1),
        ])
        .split(container[0]);

        let analysis_result = Layout::vertical([
            Constraint::Fill(1),
            Constraint::Fill(1),
            Constraint::Fill(1),
        ])
        .split(top_layout[0]);

        let items = vec![
            ListItem::new(binary_type),
            ListItem::new(entry_point),
            ListItem::new(architecture),
        ];

        List::new(items)
            .block(
                Block::bordered()
                    .fg(Color::Green)
                    .title(" BINARY METADATA ".to_span().into_centered_line()),
            )
            .render(analysis_result[0], buf);

        let items = vec![ListItem::new("content")];

        List::new(items)
            .block(
                Block::bordered()
                    .fg(Color::Green)
                    .title(" SECTION ANALYSIS ".to_span().into_centered_line()),
            )
            .render(analysis_result[1], buf);

        Block::bordered()
            .fg(Color::Green)
            .title(" YARA RULE MATCH SUMMARY ".to_span().into_centered_line())
            .render(analysis_result[2], buf);

        Block::bordered()
            .fg(Color::Green)
            .title(" ENTROPY HEATMAP (6.12) ".to_span().into_centered_line())
            .render(top_layout[1], buf);

        Block::bordered()
            .fg(Color::Green)
            .title(" RISK ASSESSMENT ".to_span().into_centered_line())
            .render(top_layout[2], buf);

        Layout::horizontal([Constraint::Fill(1)]).split(container[1]);
    }
}
