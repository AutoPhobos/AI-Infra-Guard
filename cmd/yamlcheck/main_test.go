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

package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Tencent/AI-Infra-Guard/common/fingerprints/parser"
	"github.com/Tencent/AI-Infra-Guard/pkg/vulstruct"
)

func TestFindCaseInsensitivePathCollisions(t *testing.T) {
	tests := []struct {
		name  string
		paths []string
		want  [][]string
	}{
		{
			name: "detects directory case difference",
			paths: []string{
				filepath.Join("data", "vuln", "dify", "CVE-2026-41947.yaml"),
				filepath.Join("data", "vuln", "Dify", "CVE-2026-41947.yaml"),
			},
			want: [][]string{{
				"data/vuln/Dify/CVE-2026-41947.yaml",
				"data/vuln/dify/CVE-2026-41947.yaml",
			}},
		},
		{
			name: "sorts groups and variants deterministically",
			paths: []string{
				filepath.Join("data", "vuln", "Zeta", "rule.yaml"),
				filepath.Join("data", "vuln", "LITELLM", "rule.yaml"),
				filepath.Join("data", "vuln", "zeta", "rule.yaml"),
				filepath.Join("data", "vuln", "litellm", "rule.yaml"),
				filepath.Join("data", "vuln", "LiteLLM", "rule.yaml"),
			},
			want: [][]string{
				{
					"data/vuln/LITELLM/rule.yaml",
					"data/vuln/LiteLLM/rule.yaml",
					"data/vuln/litellm/rule.yaml",
				},
				{
					"data/vuln/Zeta/rule.yaml",
					"data/vuln/zeta/rule.yaml",
				},
			},
		},
		{
			name: "ignores duplicate occurrences of an exact path",
			paths: []string{
				filepath.Join("data", "vuln", "dify", "rule.yaml"),
				filepath.Join("data", "vuln", "dify", "rule.yaml"),
			},
		},
		{
			name: "does not combine distinct roots",
			paths: []string{
				filepath.Join("data", "vuln", "dify", "rule.yaml"),
				filepath.Join("data", "vuln_en", "dify", "rule.yaml"),
			},
		},
		{
			name: "does not combine different filenames",
			paths: []string{
				filepath.Join("data", "vuln", "dify", "CVE-2026-41947.yaml"),
				filepath.Join("data", "vuln", "Dify", "CVE-2026-41949.yaml"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findCaseInsensitivePathCollisions(tt.paths)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("findCaseInsensitivePathCollisions() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestIsValidSeverity(t *testing.T) {
	tests := []struct {
		name     string
		severity string
		want     bool
	}{
		{"english low", "low", true},
		{"english medium", "MEDIUM", true},
		{"english high", "High", true},
		{"english critical", "critical", true},
		{"english info", "info", true},
		{"chinese 低", "低", true},
		{"chinese 中", "中", true},
		{"chinese 中等", "中等", true},
		{"chinese 高", "高", true},
		{"chinese 中危", "中危", true},
		{"chinese 高危", "高危", true},
		{"chinese 严重", "严重", true},
		{"chinese 危急", "危急", true},
		{"unknown", "UNKNOWN", true},
		{"empty", "", true},
		{"invalid value", "bogus", false},
		{"invalid chinese", "非常高", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidSeverity(tt.severity); got != tt.want {
				t.Errorf("isValidSeverity(%q) = %v, want %v", tt.severity, got, tt.want)
			}
		})
	}
}

func TestFindRuleNameMismatches(t *testing.T) {
	tests := []struct {
		name             string
		fingerprintNames []string
		ruleFilesByName  map[string][]string
		wantMismatches   []ruleNameMismatch
		wantOrphans      []ruleNameOrphan
	}{
		{
			name:             "rule name matching a fingerprint exactly is fine",
			fingerprintNames: []string{"vllm"},
			ruleFilesByName:  map[string][]string{"vllm": {"data/vuln/vllm/CVE-2026-54234.yaml"}},
		},
		{
			name:             "rule name differing only by case is a mismatch",
			fingerprintNames: []string{"vllm"},
			ruleFilesByName:  map[string][]string{"vLLM": {"data/vuln/vllm/CVE-2026-54234.yaml"}},
			wantMismatches: []ruleNameMismatch{{
				RuleName:        "vLLM",
				FingerprintName: "vllm",
				Files:           []string{"data/vuln/vllm/CVE-2026-54234.yaml"},
			}},
		},
		{
			name:             "mismatch reported against a mixed-case fingerprint too",
			fingerprintNames: []string{"LiteLLM"},
			ruleFilesByName:  map[string][]string{"litellm": {"data/vuln/LiteLLM/CVE-2026-70786.yaml"}},
			wantMismatches: []ruleNameMismatch{{
				RuleName:        "litellm",
				FingerprintName: "LiteLLM",
				Files:           []string{"data/vuln/LiteLLM/CVE-2026-70786.yaml"},
			}},
		},
		{
			name:             "rule name no fingerprint declares is an orphan",
			fingerprintNames: []string{"vllm"},
			ruleFilesByName:  map[string][]string{"pyload-ng": {"data/vuln/pyload-ng/CVE-2023-0055.yaml"}},
			wantOrphans: []ruleNameOrphan{{
				RuleName: "pyload-ng",
				Files:    []string{"data/vuln/pyload-ng/CVE-2023-0055.yaml"},
			}},
		},
		{
			name:             "names and files are sorted deterministically",
			fingerprintNames: []string{"flowise", "sglang", "vllm"},
			ruleFilesByName: map[string][]string{
				"vLLM": {
					"data/vuln_en/vllm/CVE-2026-90713.yaml",
					"data/vuln/vllm/CVE-2026-54234.yaml",
				},
				"SGLang":  {"data/vuln/sglang/CVE-2026-1234.yaml"},
				"Flowise": {"data/vuln/flowise/CVE-2026-5678.yaml"},
				"zzz-no-fingerprint": {
					"data/vuln_en/zzz/CVE-2026-2.yaml",
					"data/vuln/zzz/CVE-2026-1.yaml",
				},
			},
			wantMismatches: []ruleNameMismatch{
				{
					RuleName:        "Flowise",
					FingerprintName: "flowise",
					Files:           []string{"data/vuln/flowise/CVE-2026-5678.yaml"},
				},
				{
					RuleName:        "SGLang",
					FingerprintName: "sglang",
					Files:           []string{"data/vuln/sglang/CVE-2026-1234.yaml"},
				},
				{
					RuleName:        "vLLM",
					FingerprintName: "vllm",
					Files: []string{
						"data/vuln/vllm/CVE-2026-54234.yaml",
						"data/vuln_en/vllm/CVE-2026-90713.yaml",
					},
				},
			},
			wantOrphans: []ruleNameOrphan{{
				RuleName: "zzz-no-fingerprint",
				Files: []string{
					"data/vuln/zzz/CVE-2026-1.yaml",
					"data/vuln_en/zzz/CVE-2026-2.yaml",
				},
			}},
		},
		{
			name:             "suggestion is stable when fingerprints disagree on case",
			fingerprintNames: []string{"vllm", "VLLM"},
			ruleFilesByName:  map[string][]string{"vLLM": {"data/vuln/vllm/CVE-2026-54234.yaml"}},
			wantMismatches: []ruleNameMismatch{{
				RuleName:        "vLLM",
				FingerprintName: "VLLM", // lexicographically first
				Files:           []string{"data/vuln/vllm/CVE-2026-54234.yaml"},
			}},
		},
		{
			name:             "empty names are ignored on both sides",
			fingerprintNames: []string{"", "vllm"},
			ruleFilesByName:  map[string][]string{"": {"data/vuln/broken/rule.yaml"}},
		},
		{
			name:             "no fingerprints means nothing to compare against",
			fingerprintNames: nil,
			ruleFilesByName:  map[string][]string{"vLLM": {"data/vuln/vllm/CVE-2026-54234.yaml"}},
			wantOrphans: []ruleNameOrphan{{
				RuleName: "vLLM",
				Files:    []string{"data/vuln/vllm/CVE-2026-54234.yaml"},
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMismatches, gotOrphans := findRuleNameMismatches(tt.fingerprintNames, tt.ruleFilesByName)
			if !reflect.DeepEqual(gotMismatches, tt.wantMismatches) {
				t.Errorf("mismatches = %#v, want %#v", gotMismatches, tt.wantMismatches)
			}
			if !reflect.DeepEqual(gotOrphans, tt.wantOrphans) {
				t.Errorf("orphans = %#v, want %#v", gotOrphans, tt.wantOrphans)
			}
		})
	}
}

// The shipped rule library must stay free of case mismatches: every rule name
// is either spelled exactly as its fingerprint spells it, or belongs to a
// product that has no fingerprint yet.
func TestShippedRuleNamesMatchFingerprintCasing(t *testing.T) {
	fingerprintNames := collectFingerprintNames(t, filepath.Join("..", "..", "data", "fingerprints"))
	ruleFilesByName := collectRuleNames(t,
		filepath.Join("..", "..", "data", "vuln"),
		filepath.Join("..", "..", "data", "vuln_en"),
	)

	mismatches, _ := findRuleNameMismatches(fingerprintNames, ruleFilesByName)
	for _, mismatch := range mismatches {
		t.Errorf("rule name %q should be spelled %q, in: %s",
			mismatch.RuleName, mismatch.FingerprintName, strings.Join(mismatch.Files, ", "))
	}
}

func collectFingerprintNames(t *testing.T, dir string) []string {
	t.Helper()
	files, err := walkYAMLFiles(dir)
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	names := make([]string, 0, len(files))
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		fp, err := parser.InitFingerPrintFromData(data)
		if err != nil {
			t.Fatalf("parse fingerprint %s: %v", file, err)
		}
		names = append(names, strings.TrimSpace(fp.Info.Name))
	}
	return names
}

func collectRuleNames(t *testing.T, dirs ...string) map[string][]string {
	t.Helper()
	byName := make(map[string][]string)
	for _, dir := range dirs {
		files, err := walkYAMLFiles(dir)
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
		for _, file := range files {
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("read %s: %v", file, err)
			}
			vul, err := vulstruct.ReadVersionVul(data)
			if err != nil {
				t.Fatalf("parse vuln rule %s: %v", file, err)
			}
			name := strings.TrimSpace(vul.Info.FingerPrintName)
			byName[name] = append(byName[name], filepath.ToSlash(file))
		}
	}
	return byName
}

func TestPartitionOrphans(t *testing.T) {
	orphan := func(name string, files ...string) ruleNameOrphan {
		return ruleNameOrphan{RuleName: name, Files: files}
	}

	tests := []struct {
		name           string
		orphans        []ruleNameOrphan
		ruleFiles      map[string][]string
		allowed        []string
		wantUnexpected []ruleNameOrphan
		wantStale      []string
	}{
		{
			name:           "orphan outside the allowlist must fail",
			orphans:        []ruleNameOrphan{orphan("typoed-name", "data/vuln/x/CVE-1.yaml")},
			ruleFiles:      map[string][]string{"typoed-name": {"data/vuln/x/CVE-1.yaml"}},
			allowed:        []string{"pyload-ng"},
			wantUnexpected: []ruleNameOrphan{orphan("typoed-name", "data/vuln/x/CVE-1.yaml")},
		},
		{
			name:      "allowlisted orphan is exempt",
			orphans:   []ruleNameOrphan{orphan("pyload-ng", "data/vuln/pyload-ng/CVE-1.yaml")},
			ruleFiles: map[string][]string{"pyload-ng": {"data/vuln/pyload-ng/CVE-1.yaml"}},
			allowed:   []string{"pyload-ng"},
		},
		{
			name:      "allowlisted name that gained a fingerprint is stale",
			orphans:   nil,
			ruleFiles: map[string][]string{"pyload-ng": {"data/vuln/pyload-ng/CVE-1.yaml"}},
			allowed:   []string{"pyload-ng"},
			wantStale: []string{"pyload-ng"},
		},
		{
			name:      "allowlisted name absent from this run is NOT stale",
			orphans:   nil,
			ruleFiles: map[string][]string{"vllm": {"data/vuln/vllm/CVE-1.yaml"}},
			allowed:   []string{"pyload-ng", "simstudioai"},
		},
		{
			name:      "allowlist is matched exactly, not case-insensitively",
			orphans:   []ruleNameOrphan{orphan("PyLoad-NG", "data/vuln/x/CVE-1.yaml")},
			ruleFiles: map[string][]string{"PyLoad-NG": {"data/vuln/x/CVE-1.yaml"}},
			allowed:   []string{"pyload-ng"},
			// Differs only by case from the exemption, so it is not exempt:
			// the name must be fixed, not allowlisted. The exemption itself is
			// not stale either — no rule in this run carries its exact name,
			// so the run says nothing about whether that gap still exists.
			wantUnexpected: []ruleNameOrphan{orphan("PyLoad-NG", "data/vuln/x/CVE-1.yaml")},
		},
		{
			name: "stale names are sorted",
			ruleFiles: map[string][]string{
				"zeta": {"data/vuln/zeta/CVE-1.yaml"},
				"beta": {"data/vuln/beta/CVE-1.yaml"},
			},
			allowed:   []string{"zeta", "beta"},
			wantStale: []string{"beta", "zeta"},
		},
		{
			name:    "empty allowlist leaves every orphan failing",
			orphans: []ruleNameOrphan{orphan("a", "f1"), orphan("b", "f2")},
			ruleFiles: map[string][]string{
				"a": {"f1"},
				"b": {"f2"},
			},
			wantUnexpected: []ruleNameOrphan{orphan("a", "f1"), orphan("b", "f2")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotUnexpected, gotStale := partitionOrphans(tt.orphans, tt.ruleFiles, tt.allowed)
			if !reflect.DeepEqual(gotUnexpected, tt.wantUnexpected) {
				t.Errorf("unexpected = %#v, want %#v", gotUnexpected, tt.wantUnexpected)
			}
			if !reflect.DeepEqual(gotStale, tt.wantStale) {
				t.Errorf("stale = %#v, want %#v", gotStale, tt.wantStale)
			}
		})
	}
}

// TestShippedRuleNamesAreReachable is the whole-library reachability gate: a
// CVE rule can only ever surface in a scan through the name its fingerprint
// declares, so every shipped rule name must either match a fingerprint name
// exactly or be a recorded coverage gap. This catches the entire class at once
// — case drift, non-case drift (e.g. "New API" vs "new-api") and rules for
// products with no detector — rather than one product at a time.
func TestShippedRuleNamesAreReachable(t *testing.T) {
	fingerprintNames := collectFingerprintNames(t, filepath.Join("..", "..", "data", "fingerprints"))
	ruleFilesByName := collectRuleNames(t,
		filepath.Join("..", "..", "data", "vuln"),
		filepath.Join("..", "..", "data", "vuln_en"),
	)

	_, orphans := findRuleNameMismatches(fingerprintNames, ruleFilesByName)
	unexpected, stale := partitionOrphans(orphans, ruleFilesByName, knownMissingFingerprints)

	for _, orphan := range unexpected {
		t.Errorf("rule name %q has no fingerprint, so no scan can report its %d rule file(s): %s\n"+
			"\tfix the name to match a fingerprint, add a fingerprint rule, or record the gap in known_gaps.go",
			orphan.RuleName, len(orphan.Files), strings.Join(orphan.Files, ", "))
	}
	for _, name := range stale {
		t.Errorf("knownMissingFingerprints entry %q now has a fingerprint; remove it from known_gaps.go", name)
	}
}

// The allowlist is reviewed by humans and may only shrink, so keep it sorted
// and duplicate-free to stop diffs from hiding additions.
func TestKnownMissingFingerprintsIsSortedAndUnique(t *testing.T) {
	seen := make(map[string]struct{}, len(knownMissingFingerprints))
	for i, name := range knownMissingFingerprints {
		if name != strings.TrimSpace(name) || name == "" {
			t.Errorf("entry %d (%q) must be non-empty and free of surrounding whitespace", i, name)
		}
		if _, dup := seen[name]; dup {
			t.Errorf("entry %d (%q) is a duplicate", i, name)
		}
		seen[name] = struct{}{}
		if i > 0 && knownMissingFingerprints[i-1] > name {
			t.Errorf("entry %d (%q) is out of order: it should sort before %q",
				i, name, knownMissingFingerprints[i-1])
		}
	}
}
