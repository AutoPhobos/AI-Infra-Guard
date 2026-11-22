// Copyright (c) 2024-2026 Tencent Zhuque Lab. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Requirement: Any integration or derivative work must explicitly attribute
// Tencent Zhuque Lab (https://github.com/Tencent/AI-Infra-Guard) in its
// documentation or user interface, as detailed in the NOTICE file.

package main

// knownMissingFingerprints lists CVE rule names that no fingerprint rule
// declares yet. A scan cannot report any of their rules: the advisory lookup is
// keyed by the matched fingerprint's name, so a rule nothing fingerprints is
// dead weight on disk.
//
// These are therefore a coverage backlog, not a style issue — each entry means
// "A.I.G ships CVEs for this product but cannot detect it". Writing the missing
// fingerprint rule removes the entry.
//
// This list may only shrink. yamlcheck fails when a rule name outside it has no
// fingerprint (a typo, or new rules landing without a detector), AND when an
// entry in it has since gained a fingerprint (a stale exemption). Do not add a
// name here to silence a misspelling — fix the spelling instead; a name that
// differs from a fingerprint's only by case is reported separately.
var knownMissingFingerprints = []string{
	"ChatRTX",
	"ComfyUI-Ace-Nodes",
	"ComfyUI-Bmad-Nodes",
	"ComfyUI-Impact-Pack",
	"ComfyUI-Manager",
	"ai-code",
	"drupal-ai-agents", // Drupal "AI Agents" module; NOT the AI-Agent-Config fingerprint
	"guardrails-ai",
	"mcp",
	"mcp-pinot",
	"mcp-server-kubernetes",
	"pyload-ng",
	"simstudioai",
}
