# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

package agent_extension_policy

import rego.v1

policy_version := "0.1.0"

default default_global_rules := {
	"allowListOnly": false,
	"signingRules": {
		"extensionSigned": false,
		"signingDetails": {},
	},
	"updateAllowed": true,
	"uninstallAllowed": true,
}

default global_rules := {
	"allowListOnly": false,
	"signingRules": {
		"extensionSigned": false,
		"signingDetails": {},
	},
	"updateAllowed": true,
	"uninstallAllowed": true,
}

global_rules := object.union(default_global_rules, data.azureGuestAgentPolicy) if {
	data.azureGuestAgentPolicy
}

default any_extension_allowed := true

any_extension_allowed := false if {
	global_rules.allowListOnly
}

default default_signing_info := {"signingInfo": {}}

# Download rule 1: if the extension is in the list and download rule satisfied: download allowed
extensions_to_download[name] := extension if {
	some name, input_extension in input.extensions
	data.azureGuestExtensionsPolicy[name]
	download_rule_validated(input_extension, data.azureGuestExtensionsPolicy[name])
	extension := object.union(input_extension, {"downloadAllowed": true})
}

# Download rule 2: if the extension is in the list and download rule not satisfied: download denied
extensions_to_download[name] := extension if {
	some name, input_extension in input.extensions
	data.azureGuestExtensionsPolicy[name]
	not download_rule_validated(input_extension, data.azureGuestExtensionsPolicy[name])
	extension := object.union(input_extension, {"downloadAllowed": false})
}

# Download rule 3: if the extension is not in the list: depending on allowListOnly on or off
extensions_to_download[name] := extension if {
	some name, input_extension in input.extensions
	not data.azureGuestExtensionsPolicy[name]
	extension := object.union(input_extension, {"downloadAllowed": any_extension_allowed})
}

# Validate rule 1: if individual signing rule exists, signing rule validated according to the rules
extensions_validated[name] := extension if {
	some name, input_extension in input.extensions
	data.azureGuestExtensionsPolicy[name]

	extension_global_rules := object.union(global_rules, data.azureGuestExtensionsPolicy[name])
	extension_signing_info := object.union(extension_global_rules, default_signing_info)
	output := object.union(input_extension, extension_signing_info)
	signing_validated(output.signingInfo, output.signingRules)
	extension := object.union(output, {"signingValidated": true})
}

# Validate rule 2: if indivual signing rule exists, signing rule not validated according to the rules
extensions_validated[name] := extension if {
	some name, input_extension in input.extensions
	data.azureGuestExtensionsPolicy[name]

	extension_global_rules := object.union(global_rules, data.azureGuestExtensionsPolicy[name])
	extension_signing_info := object.union(extension_global_rules, default_signing_info)
	output := object.union(input_extension, extension_signing_info)
	not signing_validated(output.signingInfo, output.signingRules)
	extension := object.union(output, {"signingValidated": false})
}

# Validate rule 3: if individual signing rule doesn't exist, signing rule validated according to global signing rule
extensions_validated[name] := extension if {
	some name, input_extension in input.extensions
	not data.azureGuestExtensionsPolicy[name]
	extension_global_rules := object.union(input_extension, global_rules)
	output := object.union(extension_global_rules, default_signing_info)
	signing_validated(output.signingInfo, output.signingRules)
	extension := object.union(output, {"signingValidated": true})
}

# Validate rule 4: if individual signing rule doesn't exist, signing rule not validated according to the global rules
extensions_validated[name] := extension if {
	some name, input_extension in input.extensions
	not data.azureGuestExtensionsPolicy[name]
	extension_global_rules := object.union(input_extension, global_rules)
	output := object.union(extension_global_rules, default_signing_info)
	not signing_validated(output.signingInfo, output.signingRules)
	extension := object.union(output, {"signingValidated": false})
}

# Currently if download rules doesn't exist, allow the extension because its name is in the list.
# In the future additional rules can be checked with downloadRules present.
download_rule_validated(_, rules) if {
	not rules.downloadRules
}

# Signing is validated if input comes with extension signed, or the input of signing information is matching the
# rules in data.
signing_validated(signingInfo, signingRules) if {
	signingInfo
	signingRules
	signingInfo.extensionSigned
} else if {
	signingInfo
	signingRules
	signingInfo.extensionSigned == signingRules.extensionSigned
}
