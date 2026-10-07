//! # Scoring Engine
//!
//! This module provides severity classification ([`classifier`]) and risk assessment
//! ([`risk`]) for matched behavioral rules. The classifier maps rules to
//! [`SeverityClass`](classifier::SeverityClass) tiers, and the risk engine aggregates them into a final
//! [`RiskAssessment`](risk::RiskAssessment) with a numeric score and qualitative verdict.

pub mod classifier;
pub mod risk;
