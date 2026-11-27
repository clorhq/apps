package model

// BlockTypePrompt shows a setup prompt that visitors open or copy into an AI agent.
const BlockTypePrompt = "prompt"

// MaximumPromptCharacters keeps prefilled agent links within common URL length limits.
const MaximumPromptCharacters = 2_000

// Prompt agent IDs select the agents a prompt block offers, in the developer's order.
const (
	PromptAgentClaude     = "claude"
	PromptAgentChatGPT    = "chatgpt"
	PromptAgentClaudeCode = "claude-code"
	PromptAgentCodex      = "codex"
)
