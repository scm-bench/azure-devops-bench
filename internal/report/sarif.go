package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"

	"github.com/scm-bench/azure-devops-bench/internal/checks"
	"github.com/scm-bench/azure-devops-bench/internal/engine"
	"github.com/scm-bench/azure-devops-bench/internal/scm"
)

// SARIF 2.1.0, shaped for GitHub code scanning, which both accepts and
// displays it only under conditions its documentation is quiet about.
//
// Every result carries a physicalLocation. A result with only a
// logicalLocation is accepted by the upload and then silently dropped from
// the Security tab, so a report naming forty findings showed none. The URI is
// a path that does not exist in any repository — OpenSSF Scorecard does the
// same — built from the platform, the organization and the resource, with the
// logical location beside it saying what it really is.

const (
	sarifVersion = "2.1.0"
	// The old master/Schemata/ path 404s — oasis-tcs renamed the default
	// branch. A $schema that does not resolve fails a validating consumer.
	sarifSchema  = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
	sarifInfoURI = "https://github.com/scm-bench/azure-devops-bench"
	benchName    = "azure-devops-bench"

	// maxSARIFResults is GitHub's documented ceiling per run. Beyond it the
	// upload is rejected outright, so the worst findings are kept and the
	// rest withheld with a notice.
	maxSARIFResults = 5000
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool              sarifTool         `json:"tool"`
	AutomationDetails sarifAutomation   `json:"automationDetails"`
	Results           []sarifResult     `json:"results"`
	Invocations       []sarifInvocation `json:"invocations"`
	Properties        map[string]any    `json:"properties,omitempty"`
}

type sarifAutomation struct {
	ID string `json:"id"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string            `json:"id"`
	Name                 string            `json:"name"`
	ShortDescription     sarifText         `json:"shortDescription"`
	FullDescription      sarifText         `json:"fullDescription"`
	Help                 sarifText         `json:"help"`
	HelpURI              string            `json:"helpUri,omitempty"`
	DefaultConfiguration sarifRuleConfig   `json:"defaultConfiguration"`
	Properties           sarifRuleProperty `json:"properties"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifRuleConfig struct {
	Level string `json:"level"`
}

type sarifRuleProperty struct {
	Tags []string `json:"tags,omitempty"`
	// SecuritySeverity is the 0-10 score GitHub buckets alerts by. It is
	// absent on manual rules, so "needs a person" never displays as High.
	SecuritySeverity string `json:"security-severity,omitempty"`
	Severity         string `json:"severity,omitempty"`
	CISID            string `json:"cisId,omitempty"`
	Automated        bool   `json:"automated"`
}

type sarifResult struct {
	RuleID              string             `json:"ruleId"`
	Level               string             `json:"level"`
	Message             sarifText          `json:"message"`
	Locations           []sarifLocation    `json:"locations"`
	PartialFingerprints map[string]string  `json:"partialFingerprints"`
	Suppressions        []sarifSuppression `json:"suppressions,omitempty"`
	Properties          map[string]any     `json:"properties,omitempty"`
}

// sarifSuppression is SARIF's own way of saying a result was reviewed and
// accepted, which is what an exception is; code scanning shows the result as
// dismissed, with the justification, rather than as an open alert.
type sarifSuppression struct {
	Kind          string `json:"kind"`
	Status        string `json:"status"`
	Justification string `json:"justification"`
}

func suppressionsFor(f engine.Finding) []sarifSuppression {
	if f.Waiver == nil {
		return nil
	}
	return []sarifSuppression{{Kind: "external", Status: "accepted", Justification: acceptedNote(f.Waiver)}}
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation  `json:"physicalLocation"`
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
	EndLine     int `json:"endLine"`
	EndColumn   int `json:"endColumn"`
}

type sarifLogicalLocation struct {
	Name               string `json:"name"`
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind"`
}

type sarifInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications,omitempty"`
}

type sarifNotification struct {
	Level   string    `json:"level"`
	Message sarifText `json:"message"`
}

// instanceID names the organization a report is about, for locations,
// fingerprints and the automation ID: the host and the organization's path.
//
// The path is part of it on purpose. Every Azure DevOps Services organization
// lives on dev.azure.com, so the host alone would give two organizations the
// same automation ID — and an upload for one would close the other's alerts in
// a GitHub repository that receives both.
func instanceID(baseURL string) string {
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" {
		return escapeSegments(strings.Trim(baseURL, "/"))
	}
	id := strings.ToLower(u.Host)
	if p := strings.Trim(u.Path, "/"); p != "" {
		id += "/" + escapeSegments(p)
	}
	return id
}

// escapeSegments percent-encodes each segment of a slash-separated path.
func escapeSegments(p string) string {
	parts := strings.Split(p, "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}

// resourceURI is the physical location of a finding.
func resourceURI(instance string, f engine.Finding) string {
	resource := engine.InstanceResourceName
	if f.ResourceType == engine.ResourceRepository {
		resource = escapeSegments(f.Resource)
	}
	return scm.PlatformAzureDevOps + "/" + instance + "/" + resource
}

func writeSARIF(w io.Writer, rep *engine.Report, opts Options) error {
	instance := instanceID(rep.Metadata.BaseURL)
	rules := map[string]sarifRule{}

	// Controls no API can answer produce one result per control, not one per
	// repository: a question that needs a person is one question, and a
	// thousand identical notes would bury every real finding.
	manualByDesign := map[string][]engine.Finding{}

	var results []sarifResult
	for _, f := range rep.Findings {
		switch {
		case f.Status == engine.StatusFail:
			if _, ok := rules[f.CheckID]; !ok {
				rules[f.CheckID] = failRule(f)
			}
			results = append(results, buildResult(instance, f, f.CheckID, sarifLevel(f.Severity), f.Details, f.Resource, f.ResourceType))
		case f.Status == engine.StatusManual && !f.Automated:
			manualByDesign[f.CheckID] = append(manualByDesign[f.CheckID], f)
		case f.Status == engine.StatusManual:
			id := f.CheckID + "/manual"
			if _, ok := rules[id]; !ok {
				rules[id] = manualRule(f)
			}
			results = append(results, buildResult(instance, f, id, "note", "Manual review required: "+f.Details, f.Resource, f.ResourceType))
		}
	}
	for id, group := range manualByDesign {
		f := group[0]
		ruleID := id + "/manual"
		if _, ok := rules[ruleID]; !ok {
			rules[ruleID] = manualRule(f)
		}
		message := "Manual review required: " + f.Details
		if len(group) > 1 || f.ResourceType == engine.ResourceRepository {
			message += fmt.Sprintf(" (applies to %d %s)", len(group), plural(len(group), f.ResourceType))
		}
		results = append(results, buildResult(instance, f, ruleID, "note", message, engine.InstanceResourceName, engine.ResourceOrganization))
	}

	// Highest severity first: failures by severity, then the notes. When the
	// list is capped, what is withheld is the least severe.
	sort.SliceStable(results, func(i, j int) bool {
		a, b := results[i], results[j]
		if ra, rb := resultRank(a), resultRank(b); ra != rb {
			return ra < rb
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		return a.Message.Text < b.Message.Text
	})

	var notifications []sarifNotification
	if len(results) > maxSARIFResults {
		withheld := len(results) - maxSARIFResults
		results = results[:maxSARIFResults]
		notifications = append(notifications, sarifNotification{Level: "warning", Message: sarifText{Text: fmt.Sprintf(
			"%d of %d results were withheld to stay within GitHub code scanning's limit of %d per run; the least severe were dropped. -o json carries every finding.",
			withheld, withheld+maxSARIFResults, maxSARIFResults)}})
	}
	if results == nil {
		// A nil slice marshals to null, and run.results is typed array: a
		// strict validator rejects the file on exactly the run where nothing
		// failed.
		results = []sarifResult{}
	}

	ruleList := make([]sarifRule, 0, len(rules))
	for _, r := range rules {
		ruleList = append(ruleList, r)
	}
	sort.Slice(ruleList, func(i, j int) bool { return ruleList[i].ID < ruleList[j].ID })

	// Scan warnings, incomplete enumeration and policy errors travel as
	// invocation notifications, so a partial scan is not mistaken for a
	// clean one.
	for _, warning := range rep.Metadata.Warnings {
		notifications = append(notifications, sarifNotification{Level: "warning", Message: sarifText{Text: warning}})
	}
	for _, project := range rep.Metadata.Unlisted {
		notifications = append(notifications, sarifNotification{Level: "error", Message: sarifText{Text: "not audited: the repositories of project " + project + " could not be listed"}})
	}
	for _, e := range rep.Errors {
		notifications = append(notifications, sarifNotification{Level: "error", Message: sarifText{Text: e}})
	}

	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{
			Name:           benchName,
			Version:        opts.ToolVersion,
			InformationURI: sarifInfoURI,
			Rules:          ruleList,
		}},
		AutomationDetails: sarifAutomation{ID: benchName + "/" + instance + "/"},
		Results:           results,
		Invocations: []sarifInvocation{{
			ExecutionSuccessful:        len(rep.Errors) == 0 && len(rep.Metadata.Unlisted) == 0,
			ToolExecutionNotifications: notifications,
		}},
		Properties: map[string]any{
			"score":      rep.Score.Value,
			"passed":     rep.Score.Passed,
			"failed":     rep.Score.Failed,
			"manual":     rep.Score.Manual,
			"platform":   rep.Metadata.Platform,
			"baseUrl":    rep.Metadata.BaseURL,
			"deployment": rep.Metadata.Deployment,
		},
	}

	log := sarifLog{Schema: sarifSchema, Version: sarifVersion, Runs: []sarifRun{run}}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(log)
}

func plural(n int, kind string) string {
	noun := "resource"
	switch kind {
	case engine.ResourceRepository:
		noun = "repository"
		if n != 1 {
			noun = "repositories"
		}
		return noun
	case engine.ResourceOrganization:
		noun = "organization"
	}
	if n != 1 {
		noun += "s"
	}
	return noun
}

// resultRank orders failures by severity ahead of the notes.
func resultRank(r sarifResult) int {
	switch r.Level {
	case "error":
		return 0
	case "warning":
		return 1
	}
	if strings.HasSuffix(r.RuleID, "/manual") {
		return 3
	}
	return 2
}

func helpURI(f engine.Finding) string {
	if len(f.References) > 0 {
		return f.References[0]
	}
	return ""
}

func fullDescription(f engine.Finding) string {
	if strings.TrimSpace(f.Description) != "" {
		return f.Description
	}
	return f.Title
}

// failRule is the rule a failure is reported under, at the control's own
// severity.
func failRule(f engine.Finding) sarifRule {
	return sarifRule{
		ID:                   f.CheckID,
		Name:                 strings.ReplaceAll(f.CheckID, "-", ""),
		ShortDescription:     sarifText{Text: f.Title},
		FullDescription:      sarifText{Text: fullDescription(f)},
		Help:                 sarifText{Text: f.Remediation},
		HelpURI:              helpURI(f),
		DefaultConfiguration: sarifRuleConfig{Level: sarifLevel(f.Severity)},
		Properties: sarifRuleProperty{
			Tags:             []string{"security", "supply-chain", "cis", "source-code"},
			SecuritySeverity: securitySeverity(f.Severity),
			Severity:         strings.ToUpper(f.Severity),
			CISID:            f.CISID,
			Automated:        f.Automated,
		},
	}
}

// manualRule is the separate rule a control's MANUAL results are reported
// under.
//
// Separate because GitHub takes an alert's displayed severity from the rule,
// not the result: when one rule carried both, a control that could only report
// MANUAL — multi-factor authentication, here — arrived as an 8.0 High alert
// saying a setting was broken.
func manualRule(f engine.Finding) sarifRule {
	return sarifRule{
		ID:                   f.CheckID + "/manual",
		Name:                 strings.ReplaceAll(f.CheckID, "-", "") + "Manual",
		ShortDescription:     sarifText{Text: f.Title + " (needs manual review)"},
		FullDescription:      sarifText{Text: fullDescription(f)},
		Help:                 sarifText{Text: f.Remediation},
		HelpURI:              helpURI(f),
		DefaultConfiguration: sarifRuleConfig{Level: "note"},
		Properties: sarifRuleProperty{
			Tags:      []string{"security", "supply-chain", "cis", "source-code", "manual-review"},
			Severity:  strings.ToUpper(f.Severity),
			CISID:     f.CISID,
			Automated: f.Automated,
		},
	}
}

func buildResult(instance string, f engine.Finding, ruleID, level, details, resource, resourceType string) sarifResult {
	message := details
	if fix := f.Remediation; fix != "" {
		message += "\n\nRemediation: " + fix
	}
	located := f
	located.Resource, located.ResourceType = resource, resourceType
	kind := "repository"
	if resourceType != engine.ResourceRepository {
		kind = "organization"
	}
	return sarifResult{
		RuleID:  ruleID,
		Level:   level,
		Message: sarifText{Text: message},
		Locations: []sarifLocation{{
			PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: resourceURI(instance, located)},
				Region:           sarifRegion{StartLine: 1, StartColumn: 1, EndLine: 1, EndColumn: 1},
			},
			LogicalLocations: []sarifLogicalLocation{{
				Name:               resource,
				FullyQualifiedName: instance + "/" + resource,
				Kind:               kind,
			}},
		}},
		PartialFingerprints: map[string]string{
			// GitHub matches alerts across runs with this one; without it,
			// every upload opened fresh alerts and closed the old ones.
			"primaryLocationLineHash": lineHash(instance, f.CheckID, resource) + ":1",
			// The family's own key, stable across wording changes.
			"scmBenchFindingV1": fingerprint(f.CheckID, resource),
		},
		Suppressions: suppressionsFor(f),
		Properties: map[string]any{
			"status":       string(f.Status),
			"severity":     strings.ToUpper(f.Severity),
			"cisId":        f.CISID,
			"resourceType": resourceType,
		},
	}
}

func lineHash(instance, checkID, resource string) string {
	sum := sha256.Sum256([]byte(instance + "|" + checkID + "|" + resource))
	return hex.EncodeToString(sum[:])[:16]
}

func sarifLevel(severity string) string {
	switch strings.ToUpper(severity) {
	case checks.SeverityHigh:
		return "error"
	case checks.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func securitySeverity(severity string) string {
	switch strings.ToUpper(severity) {
	case checks.SeverityHigh:
		return "8.0"
	case checks.SeverityMedium:
		return "5.0"
	default:
		return "2.0"
	}
}

func fingerprint(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:16])
}
