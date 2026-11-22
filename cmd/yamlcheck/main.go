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

		if len(orphans) > 0 {
			fmt.Println()
			fmt.Println("⚠️  [no fingerprint] CVE rules for products with no fingerprint rule.")
			fmt.Println("    A scan cannot report these until a fingerprint declares the name:")
			for _, orphan := range orphans {
				fmt.Printf("  - %q (%d rule file(s)), e.g. %s\n",
					orphan.RuleName, len(orphan.Files), orphan.Files[0])
			}
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
// advisory engine folds case, but the knowledge API and the Python infra-attack
// module both key off the literal name), while a rule name no fingerprint
// declares at all is reported separately as a coverage gap.
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