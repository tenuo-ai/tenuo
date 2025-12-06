//! MCP (Model Context Protocol) Integration Helpers
//!
//! This module provides configuration and helpers for integrating Tenuo with MCP servers.
//! Unlike the HTTP gateway, MCP is tool-centric, so we don't need route matching.
//! We just need to map MCP tool names to Tenuo tool configurations.
//!
//! # What is MCP?
//!
//! The [Model Context Protocol](https://modelcontextprotocol.io) is an open protocol for
//! connecting AI assistants to external data sources and tools. MCP servers expose tools that
//! AI models can call, and Tenuo provides authorization for those tool calls.
//!
//! # Why MCP + Tenuo?
//!
//! **Native AI Agent Integration**: MCP is the standard protocol for AI agent tool calling.
//! Tenuo's MCP integration means you can secure AI agent workflows without custom middleware.
//!
//! **Tool-Centric Authorization**: MCP tools map directly to Tenuo tool configurations.
//! No HTTP routing complexity—just map tool names to constraints.
//!
//! **Cryptographic Provenance**: Every tool call is authorized by a warrant chain that proves
//! who delegated the authority and what bounds apply. Perfect for multi-agent workflows where
//! an orchestrator delegates to specialized workers.
//!
//! # Example
//!
//! ```yaml
//! # mcp-config.yaml
//! version: "1"
//! settings:
//!   trusted_issuers:
//!     - "f32e74b5a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8"
//!
//! tools:
//!   filesystem_read:
//!     description: "Read files from the filesystem"
//!     constraints:
//!       path:
//!         from: body
//!         path: "path"
//!         required: true
//!       max_size:
//!         from: body
//!         path: "maxSize"
//!         type: integer
//!         default: 1048576
//! ```
//!
//! ```rust,ignore
//! use tenuo_core::{Authorizer, CompiledMcpConfig, McpConfig, PublicKey, wire};
//! use serde_json::json;
//!
//! // Load and compile configuration
//! let config = McpConfig::from_file("mcp-config.yaml")?;
//! let compiled = CompiledMcpConfig::compile(config);
//!
//! // Validate configuration (warns about incompatible extraction sources)
//! let warnings = compiled.validate();
//! for warning in warnings {
//!     eprintln!("Warning: {}", warning);
//! }
//!
//! // Initialize authorizer with trusted Control Plane key
//! let control_plane_key_bytes: [u8; 32] = hex::decode("f32e74b5...")?.try_into().unwrap();
//! let control_plane_key = PublicKey::from_bytes(&control_plane_key_bytes)?;
//! let authorizer = Authorizer::new(control_plane_key);
//!
//! // MCP tool call arrives from AI agent
//! let arguments = json!({
//!     "path": "/var/log/app.log",
//!     "maxSize": 1024
//! });
//!
//! // 1. Extract constraints from MCP arguments
//! let result = compiled.extract_constraints("filesystem_read", &arguments)?;
//! // result.constraints contains: {"path": "String(...)", "max_size": "Integer(1024)"}
//!
//! // 2. Decode warrant chain (from MCP request metadata)
//! let warrant = wire::decode_base64(&warrant_chain_base64)?;
//!
//! // 3. Authorize the action using extracted constraints
//! authorizer.check(
//!     &warrant,
//!     "filesystem_read",
//!     &result.constraints,
//!     pop_signature.as_ref()  // Optional PoP signature
//! )?;
//!
//! // 4. If authorized, execute the tool
//! // execute_filesystem_read(arguments);
//! ```
//!
//! # Extraction Source Compatibility
//!
//! MCP tool calls only provide an `arguments` JSON object. Extraction rules should use:
//! - `from: body` - Extract from the arguments object (recommended)
//! - `from: literal` - Use a default/literal value
//!
//! Rules using `from: path`, `from: query`, or `from: header` will not work in MCP context
//! and will be flagged by `validate()`.

use crate::extraction::{
    CompiledExtractionRules, ExtractionError, ExtractionSource, RequestContext,
};
use crate::gateway_config::{ExtractionResult, ToolConfig};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// MCP Gateway Configuration.
///
/// Simpler than `GatewayConfig` as it doesn't need HTTP routing.
/// It maps MCP tool names directly to Tenuo tool configurations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpConfig {
    /// Configuration version
    pub version: String,
    /// Global settings
    pub settings: McpSettings,
    /// Tool definitions
    /// Key: MCP Tool Name
    /// Value: Tenuo Tool Configuration
    pub tools: HashMap<String, ToolConfig>,
}

/// Global MCP settings.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct McpSettings {
    /// Trusted Control Plane public keys (hex)
    #[serde(default)]
    pub trusted_issuers: Vec<String>,
}

/// Compiled MCP Configuration for performance.
pub struct CompiledMcpConfig {
    pub settings: McpSettings,
    /// Map of MCP Tool Name -> Compiled Rules
    pub tools: HashMap<String, CompiledTool>,
}

pub struct CompiledTool {
    pub config: ToolConfig,
    pub extraction_rules: CompiledExtractionRules,
}

impl McpConfig {
    /// Load configuration from a file.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, crate::gateway_config::ConfigError> {
        let content = std::fs::read_to_string(path.as_ref())
            .map_err(|e| crate::gateway_config::ConfigError::FileRead(path.as_ref().display().to_string(), e))?;
        serde_yaml::from_str(&content).map_err(crate::gateway_config::ConfigError::YamlParse)
    }
}

impl CompiledMcpConfig {
    /// Compile the configuration.
    pub fn compile(config: McpConfig) -> Self {
        let mut tools = HashMap::new();

        for (name, tool_config) in config.tools {
            let rules = CompiledExtractionRules::compile(tool_config.constraints.clone());
            tools.insert(name, CompiledTool {
                config: tool_config,
                extraction_rules: rules,
            });
        }

        Self {
            settings: config.settings,
            tools,
        }
    }

    /// Validate that extraction rules are compatible with MCP (body-only).
    ///
    /// MCP tool calls only provide an `arguments` JSON object, so extraction rules
    /// should use `from: body` or `from: literal`. Rules using `from: path`,
    /// `from: query`, or `from: header` will not work and will be flagged here.
    ///
    /// Returns a list of warning messages for incompatible rules.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let config = McpConfig::from_file("mcp-config.yaml")?;
    /// let compiled = CompiledMcpConfig::compile(config);
    ///
    /// let warnings = compiled.validate();
    /// for warning in warnings {
    ///     eprintln!("Warning: {}", warning);
    /// }
    /// ```
    pub fn validate(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        for (tool_name, compiled_tool) in &self.tools {
            for (field_name, rule) in &compiled_tool.extraction_rules.rules {
                match rule.rule.from {
                    ExtractionSource::Path | ExtractionSource::Query | ExtractionSource::Header => {
                        warnings.push(format!(
                            "Tool '{}' field '{}' uses {:?} source, which won't work in MCP (only body/literal supported)",
                            tool_name, field_name, rule.rule.from
                        ));
                    }
                    ExtractionSource::Body | ExtractionSource::Literal => {
                        // These are fine
                    }
                }
            }
        }
        warnings
    }

    /// Extract constraints from an MCP tool call.
    ///
    /// `tool_name`: The name of the tool being called.
    /// `arguments`: The arguments object from the MCP request.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let arguments = json!({
    ///     "path": "/var/log/app.log",
    ///     "maxSize": 1024
    /// });
    ///
    /// let result = compiled.extract_constraints("filesystem_read", &arguments)?;
    /// // result.constraints contains extracted values
    /// ```
    pub fn extract_constraints(
        &self,
        tool_name: &str,
        arguments: &serde_json::Value,
    ) -> Result<ExtractionResult, ExtractionError> {
        let tool = self.tools.get(tool_name).ok_or_else(|| ExtractionError {
            field: "tool".to_string(),
            source: ExtractionSource::Literal,
            path: tool_name.to_string(),
            hint: format!("Tool '{}' not defined in Tenuo configuration", tool_name),
            required: true,
        })?;

        // Create context from arguments (treated as body)
        let ctx = RequestContext::with_body(arguments.clone());

        let (constraints, traces) = tool.extraction_rules.extract_all(&ctx)?;

        Ok(ExtractionResult {
            constraints,
            traces,
            tool: tool_name.to_string(),
        })
    }
}
