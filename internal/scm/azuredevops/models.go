package azuredevops

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
)

// The types below decode only the fields a rule depends on, and decode them
// tolerantly: Microsoft's own samples disagree with each other about shapes
// (a project state is "wellFormed" in one sample and 1 in another; an identity
// descriptor is a string in responses and an object in the reference), and a
// decode error on a field nobody reads would cost a whole repository's verdicts.

// apiProject is a TeamProjectReference.
type apiProject struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	// Visibility is "private" or "public" — or, on older servers, a number.
	Visibility flexString `json:"visibility"`
}

// apiRepository is a GitRepository.
type apiRepository struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	DefaultBranch string     `json:"defaultBranch"`
	IsDisabled    bool       `json:"isDisabled"`
	IsFork        bool       `json:"isFork"`
	Project       apiProject `json:"project"`
	Parent        *struct {
		Name    string     `json:"name"`
		Project apiProject `json:"project"`
	} `json:"parentRepository"`
}

// apiRef is a GitRef.
type apiRef struct {
	Name     string       `json:"name"`
	ObjectID string       `json:"objectId"`
	Creator  *apiIdentRef `json:"creator"`
	IsLocked bool         `json:"isLocked"`
}

// apiIdentRef is an IdentityRef: who created a ref, who created a policy.
type apiIdentRef struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	UniqueName  string `json:"uniqueName"`
	Descriptor  string `json:"descriptor"`
}

// apiBranchStats is a GitBranchStats.
type apiBranchStats struct {
	Name   string `json:"name"`
	Commit struct {
		CommitID  string `json:"commitId"`
		Committer struct {
			Date string `json:"date"`
		} `json:"committer"`
		Author struct {
			Date string `json:"date"`
		} `json:"author"`
	} `json:"commit"`
}

// apiItem is a GitItem.
type apiItem struct {
	Path          string `json:"path"`
	GitObjectType string `json:"gitObjectType"`
	IsFolder      bool   `json:"isFolder"`
}

// apiPolicy is a PolicyConfiguration.
type apiPolicy struct {
	ID         int             `json:"id"`
	IsEnabled  bool            `json:"isEnabled"`
	IsBlocking bool            `json:"isBlocking"`
	IsDeleted  bool            `json:"isDeleted"`
	Type       apiPolicyType   `json:"type"`
	Settings   json.RawMessage `json:"settings"`
}

type apiPolicyType struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
}

// policyScope is one element of settings.scope: a configuration applies when
// any element matches.
type policyScope struct {
	RepositoryID *string `json:"repositoryId"`
	RefName      *string `json:"refName"`
	MatchKind    string  `json:"matchKind"`
}

// policySettings is the union of the settings this bench reads, across
// policy types. Absent fields decode to their zero value, which for each one
// below is also the platform's default.
type policySettings struct {
	Scope []policyScope `json:"scope"`

	// Minimum number of reviewers.
	MinimumApproverCount        flexInt  `json:"minimumApproverCount"`
	CreatorVoteCounts           flexBool `json:"creatorVoteCounts"`
	AllowDownvotes              flexBool `json:"allowDownvotes"`
	ResetOnSourcePush           flexBool `json:"resetOnSourcePush"`
	ResetRejectionsOnSourcePush flexBool `json:"resetRejectionsOnSourcePush"`
	RequireVoteOnLastIteration  flexBool `json:"requireVoteOnLastIteration"`
	RequireVoteOnEachIteration  flexBool `json:"requireVoteOnEachIteration"`
	BlockLastPusherVote         flexBool `json:"blockLastPusherVote"`

	// Build validation.
	BuildDefinitionID       flexInt   `json:"buildDefinitionId"`
	DisplayName             string    `json:"displayName"`
	ManualQueueOnly         flexBool  `json:"manualQueueOnly"`
	QueueOnSourceUpdateOnly flexBool  `json:"queueOnSourceUpdateOnly"`
	ValidDuration           flexFloat `json:"validDuration"`
	FilenamePatterns        []string  `json:"filenamePatterns"`

	// Status.
	StatusName               string   `json:"statusName"`
	StatusGenre              string   `json:"statusGenre"`
	PolicyApplicability      *flexInt `json:"policyApplicability"`
	DefaultDisplayName       string   `json:"defaultDisplayName"`
	InvalidateOnSourceUpdate flexBool `json:"invalidateOnSourceUpdate"`

	// Require a merge strategy.
	AllowSquash        flexBool `json:"allowSquash"`
	AllowNoFastForward flexBool `json:"allowNoFastForward"`
	AllowRebase        flexBool `json:"allowRebase"`
	AllowRebaseMerge   flexBool `json:"allowRebaseMerge"`
	UseSquashMerge     flexBool `json:"useSquashMerge"`

	// Required (automatically included) reviewers.
	RequiredReviewerIDs []string `json:"requiredReviewerIds"`
	AddedFilesOnly      flexBool `json:"addedFilesOnly"`
}

// apiACL is an AccessControlList.
type apiACL struct {
	Token               string            `json:"token"`
	InheritPermissions  bool              `json:"inheritPermissions"`
	IncludeExtendedInfo *bool             `json:"includeExtendedInfo"`
	AcesDictionary      map[string]apiACE `json:"acesDictionary"`
}

// apiACE is an AccessControlEntry.
type apiACE struct {
	Descriptor   string          `json:"descriptor"`
	Allow        int64           `json:"allow"`
	Deny         int64           `json:"deny"`
	ExtendedInfo *apiACEExtended `json:"extendedInfo"`
}

// apiACEExtended carries the server's own evaluation of an identity's rights
// on a token. Zero values are omitted from the wire, so a missing field is a
// zero — but a missing object is not.
type apiACEExtended struct {
	EffectiveAllow int64 `json:"effectiveAllow"`
	EffectiveDeny  int64 `json:"effectiveDeny"`
	InheritedAllow int64 `json:"inheritedAllow"`
	InheritedDeny  int64 `json:"inheritedDeny"`
}

// apiNamespace is a SecurityNamespaceDescription.
type apiNamespace struct {
	NamespaceID string `json:"namespaceId"`
	Name        string `json:"name"`
	Actions     []struct {
		Bit         int64  `json:"bit"`
		Name        string `json:"name"`
		DisplayName string `json:"displayName"`
	} `json:"actions"`
}

// apiIdentity is an IMS Identity.
type apiIdentity struct {
	ID                  string                     `json:"id"`
	Descriptor          identityDescriptor         `json:"descriptor"`
	SubjectDescriptor   string                     `json:"subjectDescriptor"`
	ProviderDisplayName string                     `json:"providerDisplayName"`
	CustomDisplayName   string                     `json:"customDisplayName"`
	IsActive            bool                       `json:"isActive"`
	IsContainer         bool                       `json:"isContainer"`
	Members             []identityDescriptor       `json:"members"`
	Properties          map[string]json.RawMessage `json:"properties"`
}

// property reads a value from an IMS property bag, where each entry is
// {"$type": ..., "$value": ...}.
func (i apiIdentity) property(name string) string {
	raw, ok := i.Properties[name]
	if !ok {
		return ""
	}
	var wrapped struct {
		Value json.RawMessage `json:"$value"`
	}
	if err := json.Unmarshal(raw, &wrapped); err == nil && len(wrapped.Value) > 0 {
		raw = wrapped.Value
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return strings.Trim(string(raw), `"`)
}

// identityDescriptor is "Type;Identifier". IMS writes it as a string, and its
// reference documents it as {identityType, identifier}; both are accepted.
type identityDescriptor string

func (d *identityDescriptor) UnmarshalJSON(raw []byte) error {
	raw = bytes.TrimSpace(raw)
	if bytes.Equal(raw, []byte("null")) {
		*d = ""
		return nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		*d = identityDescriptor(s)
		return nil
	}
	var obj struct {
		IdentityType string `json:"identityType"`
		Identifier   string `json:"identifier"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return err
	}
	if obj.IdentityType == "" && obj.Identifier == "" {
		*d = ""
		return nil
	}
	*d = identityDescriptor(obj.IdentityType + ";" + obj.Identifier)
	return nil
}

// apiMembership is a GraphMembership.
type apiMembership struct {
	ContainerDescriptor string `json:"containerDescriptor"`
	MemberDescriptor    string `json:"memberDescriptor"`
}

// apiUserEntitlement is a UserEntitlement.
type apiUserEntitlement struct {
	ID          string `json:"id"`
	AccessLevel struct {
		AccountLicenseType string `json:"accountLicenseType"`
		LicenseDisplayName string `json:"licenseDisplayName"`
		Status             string `json:"status"`
	} `json:"accessLevel"`
	DateCreated      string `json:"dateCreated"`
	LastAccessedDate string `json:"lastAccessedDate"`
	User             struct {
		PrincipalName string `json:"principalName"`
		DisplayName   string `json:"displayName"`
		MailAddress   string `json:"mailAddress"`
		MetaType      string `json:"metaType"`
		Origin        string `json:"origin"`
		Descriptor    string `json:"descriptor"`
		SubjectKind   string `json:"subjectKind"`
	} `json:"user"`
}

// apiAdvSecOrg is the organization's Advanced Security enablement.
type apiAdvSecOrg struct {
	ReposEnablementStatus []apiAdvSecRepo `json:"reposEnablementStatus"`
}

type apiAdvSecRepo struct {
	ProjectID                string `json:"projectId"`
	RepositoryID             string `json:"repositoryId"`
	SecretProtectionFeatures *struct {
		SecretProtectionEnabled *bool `json:"secretProtectionEnabled"`
		BlockPushes             *bool `json:"blockPushes"`
	} `json:"secretProtectionFeatures"`
	CodeSecurityFeatures *struct {
		CodeSecurityEnabled                *bool `json:"codeSecurityEnabled"`
		CodeQLEnabled                      *bool `json:"codeQLEnabled"`
		DependencyScanningInjectionEnabled *bool `json:"dependencyScanningInjectionEnabled"`
	} `json:"codeSecurityFeatures"`
}

// flexString accepts a JSON string or number and keeps its text.
type flexString string

func (s *flexString) UnmarshalJSON(raw []byte) error {
	raw = bytes.TrimSpace(raw)
	if bytes.Equal(raw, []byte("null")) {
		*s = ""
		return nil
	}
	var str string
	if err := json.Unmarshal(raw, &str); err == nil {
		*s = flexString(str)
		return nil
	}
	*s = flexString(string(raw))
	return nil
}

// flexBool accepts true/false, "true"/"false", and null as false.
type flexBool bool

func (b *flexBool) UnmarshalJSON(raw []byte) error {
	raw = bytes.TrimSpace(raw)
	switch strings.ToLower(strings.Trim(string(raw), `"`)) {
	case "true", "1":
		*b = true
	default:
		*b = false
	}
	return nil
}

// flexInt accepts a number or a numeric string, and null as zero.
type flexInt int

func (n *flexInt) UnmarshalJSON(raw []byte) error {
	text := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	if text == "" || text == "null" {
		*n = 0
		return nil
	}
	f, err := strconv.ParseFloat(text, 64)
	if err != nil {
		return err
	}
	*n = flexInt(int(f))
	return nil
}

// flexFloat accepts a number or numeric string, and null as zero.
type flexFloat float64

func (f *flexFloat) UnmarshalJSON(raw []byte) error {
	text := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	if text == "" || text == "null" {
		*f = 0
		return nil
	}
	v, err := strconv.ParseFloat(text, 64)
	if err != nil {
		return err
	}
	*f = flexFloat(v)
	return nil
}
