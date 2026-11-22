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

// Package main YAML format validation tool
// Used in CI pipelines to verify the format of YAML files under the data directory.
// Usage: yamlcheck <path1> [path2] ...
// Supports files or directories; directories are scanned recursively for .yaml/.yml files.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Tencent/AI-Infra-Guard/common/fingerprints/parser"
	"github.com/Tencent/AI-Infra-Guard/pkg/vulstruct"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: yamlcheck <path1> [path2] ...")
		fmt.Println("  path can be a file or directory (directories are scanned recursively)")
		fmt.Println("  Validates YAML files under data/fingerprints, data/vuln, data/vuln_en")
		os.Exit(1)
	}

	// Collect all YAML files to check
	var yamlFiles []string
	for _, arg := range os.Args[1:] {
		info, err := os.Stat(arg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ [path error] %s: %v\n", arg, err)
			continue
		}
		if info.IsDir() {
			files, err := walkYAMLFiles(arg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "❌ [directory walk failed] %s: %v\n", arg, err)
				continue
			}
			yamlFiles = append(yamlFiles, files...)
		} else {
			if isYAML(arg) {
				yamlFiles = append(yamlFiles, arg)
			}
		}
	}

	if collisions := findCaseInsensitivePathCollisions(yamlFiles); len(collisions) > 0 {
		fmt.Fprintln(os.Stderr, "❌ [case-insensitive path collision] conflicting YAML paths found:")
		for _, collision := range collisions {
			fmt.Fprintf(os.Stderr, "  - %s\n", strings.Join(collision, " | "))
		}
		os.Exit(1)
	}

	hasError := false
	checkedCount := 0
	passCount := 0
	failCount := 0

	// Names declared by the fingerprint rules, and the rule files that refer
	// to each name, collected for the cross-reference check below.
	var fingerprintNames []string
	ruleFilesByName := make(map[string][]string)

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════╗")
	fmt.Println("║          AIG YAML Validation Report          ║")
	fmt.Println("╚══════════════════════════════════════════════╝")
	fmt.Println()

	for _, file := range yamlFiles {
		category := categorizeFile(file)
		if category == "" {
			continue
		}

		checkedCount++
		data, err := os.ReadFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ❌  FAIL  [read error]  %s\n      └─ %v\n", file, err)
			hasError = true
			failCount++
			continue
		}

		switch category {
		case "fingerprint":
			fp, err := parser.InitFingerPrintFromData(data)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  ❌  FAIL  [fingerprint]  %s\n      └─ %v\n", file, err)
				hasError = true
				failCount++
			} else if strings.TrimSpace(fp.Info.Name) == "" {
				fmt.Fprintf(os.Stderr, "  ❌  FAIL  [fingerprint]  %s\n      └─ missing required 'name' field\n", file)
				hasError = true
				failCount++
			} else {
				fingerprintNames = append(fingerprintNames, strings.TrimSpace(fp.Info.Name))
				fmt.Printf("  ✅  PASS  [fingerprint]  %s\n", file)
				passCount++
			}
		case "vuln":
			vul, err := vulstruct.ReadVersionVul(data)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  ❌  FAIL  [vuln rule]   %s\n      └─ %v\n", file, err)
				hasError = true
				failCount++
			} else if strings.TrimSpace(vul.Info.FingerPrintName) == "" {
				fmt.Fprintf(os.Stderr, "  ❌  FAIL  [vuln rule]   %s\n      └─ missing required 'name' field\n", file)
				hasError = true
				failCount++
			} else if !isValidSeverity(vul.Info.Severity) {
				fmt.Fprintf(os.Stderr, "  ❌  FAIL  [vuln rule]   %s\n      └─ invalid or missing severity level '%s'\n", file, vul.Info.Severity)
				hasError = true
				failCount++
			} else {
				name := strings.TrimSpace(vul.Info.FingerPrintName)
				ruleFilesByName[name] = append(ruleFilesByName[name], filepath.ToSlash(file))
				fmt.Printf("  ✅  PASS  [vuln rule]   %s\n", file)
				passCount++
			}
		}
	}

	// Cross-reference rule names against fingerprint names. Only meaningful
	// when fingerprints were part of this run; validating data/vuln on its own
	// says nothing about which names exist.
	if len(fingerprintNames) > 0 && len(ruleFilesByName) > 0 {
		mismatches, orphans := findRuleNameMismatches(fingerprintNames, ruleFilesByName)

		unexpected, stale := partitionOrphans(orphans, ruleFilesByName, knownMissingFingerprints)

		if len(unexpected) > 0 {
			hasError = true
			fmt.Println()
			fmt.Fprintln(os.Stderr, "❌ [no fingerprint] CVE rules for products no fingerprint rule declares.")
			fmt.Fprintln(os.Stderr, "    A scan looks advisories up by the matched fingerprint's name, so no scan can")
			fmt.Fprintln(os.Stderr, "    ever report these rules. Either fix the name to match an existing")
			fmt.Fprintln(os.Stderr, "    fingerprint, or add a fingerprint rule that declares it:")
			for _, orphan := range unexpected {
				fmt.Fprintf(os.Stderr, "  - %q (%d rule file(s)):\n", orphan.RuleName, len(orphan.Files))
				for _, file := range orphan.Files {
					fmt.Fprintf(os.Stderr, "      └─ %s\n", file)
				}
			}
			fmt.Fprintln(os.Stderr, "    If the product genuinely has no detector yet and writing one is out of scope,")
			fmt.Fprintln(os.Stderr, "    add the name to knownMissingFingerprints in cmd/yamlcheck/known_gaps.go.")
		}

		if len(stale) > 0 {
			hasError = true
			fmt.Println()
			fmt.Fprintln(os.Stderr, "❌ [stale exemption] knownMissingFingerprints names that now HAVE a fingerprint.")
			fmt.Fprintln(os.Stderr, "    The coverage gap is closed; remove these from cmd/yamlcheck/known_gaps.go")
			fmt.Fprintln(os.Stderr, "    so the list keeps shrinking:")
			for _, name := range stale {
				fmt.Fprintf(os.Stderr, "  - %q\n", name)
			}
		}

		if exempted := len(orphans) - len(unexpected); exempted > 0 {
			fmt.Println()
			fmt.Printf("⚠️  [known coverage gap] %d rule name(s) have no fingerprint yet and are\n", exempted)
			fmt.Println("    exempted in cmd/yamlcheck/known_gaps.go. No scan can report their rules.")
		}

		if len(mismatches) > 0 {
			hasError = true
			fmt.Println()
			fmt.Fprintln(os.Stderr, "❌ [name case mismatch] rule 'name' differs from the fingerprint's 'name' only by case.")
			fmt.Fprintln(os.Stderr, "    The scanner looks advisories up by the matched fingerprint's name, and the")
			fmt.Fprintln(os.Stderr, "    knowledge API derives a rule's directory from it, so spell it the same way:")
			for _, mismatch := range mismatches {
				fmt.Fprintf(os.Stderr, "  - %q should be %q (%d rule file(s)):\n",
					mismatch.RuleName, mismatch.FingerprintName, len(mismatch.Files))
				for _, file := range mismatch.Files {
					fmt.Fprintf(os.Stderr, "      └─ %s\n", file)
				}
			}
		}
	}

	fmt.Println()
	fmt.Println("──────────────────────────────────────────────")

	if checkedCount == 0 {
		fmt.Println("⚠️  No YAML files found to validate.")
		os.Exit(0)
	}

	fmt.Printf("  Total checked : %d\n", checkedCount)
	fmt.Printf("  ✅ Passed     : %d\n", passCount)
	fmt.Printf("  ❌ Failed     : %d\n", failCount)
	fmt.Println("──────────────────────────────────────────────")

	if hasError {
		fmt.Println()
		fmt.Fprintln(os.Stderr, "❌ Validation FAILED — please fix the errors listed above.")
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println("✅ All YAML files passed validation!")
}

// isValidSeverity verifies that severity matches standard vulnerability levels.
// Accepts both English (low/medium/high/critical) and Chinese (低/中/高/严重/危急)
// severity labels used across the zh/en rule libraries, plus UNKNOWN/"" for
// rules where no CVSS score is available (e.g. supply-chain advisories).
func isValidSeverity(severity string) bool {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "info", "low", "medium", "high", "critical",
		"信息", "低", "中", "中等", "高", "中危", "高危", "严重", "危急",
		"unknown", "":
		return true
	default:
		return false
	}
}

// ruleNameMismatch is a CVE rule 'name' that matches a fingerprint 'name'
// only after folding case, e.g. rule "vLLM" against fingerprint "vllm".
type ruleNameMismatch struct {
	RuleName        string
	FingerprintName string
	Files           []string
}

// ruleNameOrphan is a CVE rule 'name' that no fingerprint declares at all,
// in any casing — the product has rules but no fingerprint yet.
type ruleNameOrphan struct {
	RuleName string
	Files    []string
}

// findRuleNameMismatches cross-references CVE rule names against fingerprint
// names. A rule is reachable from a scan only through the name its fingerprint
// declares, so a rule whose name differs in case is a defect to fix (the
// advisory engine folds case, but the knowledge API derives a rule's on-disk
// directory from the literal name, so the two spellings must still agree),
// while a rule name no fingerprint declares at all is returned separately —
// nothing can reach those rules, whatever the comparison.
//
// Both results are sorted by rule name, and each file list is sorted, so the
// output is stable across runs.
func findRuleNameMismatches(fingerprintNames []string, ruleFilesByName map[string][]string) ([]ruleNameMismatch, []ruleNameOrphan) {
	// Fold fingerprint names, keeping the lexicographically first spelling so
	// the suggestion is deterministic even if two fingerprints disagree.
	folded := make(map[string]string, len(fingerprintNames))
	exact := make(map[string]struct{}, len(fingerprintNames))
	for _, name := range fingerprintNames {
		if name == "" {
			continue
		}
		exact[name] = struct{}{}
		key := strings.ToLower(name)
		if current, ok := folded[key]; !ok || name < current {
			folded[key] = name
		}
	}

	ruleNames := make([]string, 0, len(ruleFilesByName))
	for name := range ruleFilesByName {
		ruleNames = append(ruleNames, name)
	}
	sort.Strings(ruleNames)

	var mismatches []ruleNameMismatch
	var orphans []ruleNameOrphan
	for _, name := range ruleNames {
		if name == "" {
			continue
		}
		if _, ok := exact[name]; ok {
			continue
		}
		files := make([]string, len(ruleFilesByName[name]))
		copy(files, ruleFilesByName[name])
		sort.Strings(files)

		if fingerprintName, ok := folded[strings.ToLower(name)]; ok {
			mismatches = append(mismatches, ruleNameMismatch{
				RuleName:        name,
				FingerprintName: fingerprintName,
				Files:           files,
			})
			continue
		}
		orphans = append(orphans, ruleNameOrphan{RuleName: name, Files: files})
	}

	return mismatches, orphans
}

// partitionOrphans splits rule names that no fingerprint declares into the ones
// that must fail the run and the exemptions that are no longer needed.
//
// unexpected: an orphan absent from the allowlist. No scan can report its
// rules, so it fails the run — either the name is wrong, or the product needs a
// fingerprint rule.
//
// stale: an allowlist entry whose rules are in this run but that is no longer
// an orphan, i.e. a fingerprint now declares it. Failing on these is what keeps
// the allowlist shrink-only; an exemption that outlives its gap would silently
// re-open the hole it covered. An entry whose rules are absent from this run is
// NOT stale — a partial run (say `yamlcheck data/fingerprints data/vuln/vllm`)
// says nothing about products it did not look at.
//
// Allowlist entries are matched exactly, not case-insensitively: a name that
// differs from a fingerprint's only by case is already reported as a mismatch,
// and must be fixed rather than exempted.
//
// Both results are sorted, so the output is stable across runs.
func partitionOrphans(orphans []ruleNameOrphan, ruleFilesByName map[string][]string, allowed []string) ([]ruleNameOrphan, []string) {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, name := range allowed {
		allowedSet[name] = struct{}{}
	}

	orphanSet := make(map[string]struct{}, len(orphans))
	var unexpected []ruleNameOrphan
	for _, orphan := range orphans {
		orphanSet[orphan.RuleName] = struct{}{}
		if _, ok := allowedSet[orphan.RuleName]; !ok {
			unexpected = append(unexpected, orphan)
		}
	}

	var stale []string
	for _, name := range allowed {
		if _, inRun := ruleFilesByName[name]; !inRun {
			continue
		}
		if _, isOrphan := orphanSet[name]; !isOrphan {
			stale = append(stale, name)
		}
	}
	sort.Strings(stale)

	// findRuleNameMismatches already returns orphans sorted by rule name, and
	// filtering preserves that order.
	return unexpected, stale
}

// findCaseInsensitivePathCollisions returns distinct paths that become equal
// after normalizing separators and folding case. Duplicate occurrences of the
// exact same normalized path are ignored.
func findCaseInsensitivePathCollisions(paths []string) [][]string {
	grouped := make(map[string]map[string]struct{})
	for _, path := range paths {
		normalized := filepath.ToSlash(filepath.Clean(path))
		folded := strings.ToLower(normalized)
		if grouped[folded] == nil {
			grouped[folded] = make(map[string]struct{})
		}
		grouped[folded][normalized] = struct{}{}
	}

	var foldedPaths []string
	for folded, originals := range grouped {
		if len(originals) > 1 {
			foldedPaths = append(foldedPaths, folded)
		}
	}
	sort.Strings(foldedPaths)

	var collisions [][]string
	for _, folded := range foldedPaths {
		originals := make([]string, 0, len(grouped[folded]))
		for original := range grouped[folded] {
			originals = append(originals, original)
		}
		sort.Strings(originals)
		collisions = append(collisions, originals)
	}

	return collisions
}

// walkYAMLFiles recursively walks a directory and returns all .yaml/.yml file paths.
func walkYAMLFiles(root string) ([]string, error) {
	var files []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && isYAML(path) {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

// isYAML reports whether the file has a .yaml or .yml extension.
func isYAML(file string) bool {
	return strings.HasSuffix(file, ".yaml") || strings.HasSuffix(file, ".yml")
}

// categorizeFile determines the category of a YAML file based on its path.
// Returns "fingerprint", "vuln", or "" (not a file that needs validation).
func categorizeFile(file string) string {
	normalized := filepath.ToSlash(file)

	if strings.Contains(normalized, "data/fingerprints/") || strings.HasPrefix(normalized, "fingerprints/") {
		return "fingerprint"
	}

	if strings.Contains(normalized, "data/vuln/") || strings.Contains(normalized, "data/vuln_en/") ||
		strings.HasPrefix(normalized, "vuln/") || strings.HasPrefix(normalized, "vuln_en/") {
		return "vuln"
	}

	return ""
}
