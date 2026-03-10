with open('group/integration_test.go', 'r') as f:
    content = f.read()

old_code = """	// Keep both group instances aligned on epoch secrets for message roundtrip checks.
	bobGroup.EpochSecrets = aliceGroup.EpochSecrets"""

new_code = """	// Keep both group instances aligned on epoch secrets for message roundtrip checks.
	bobGroup.EpochSecrets = &schedule.EpochSecrets{
		InitSecret:       aliceGroup.EpochSecrets.InitSecret.Clone(),
		SenderDataSecret: aliceGroup.EpochSecrets.SenderDataSecret.Clone(),
		EncryptionSecret: aliceGroup.EpochSecrets.EncryptionSecret.Clone(),
		ExporterSecret:   aliceGroup.EpochSecrets.ExporterSecret.Clone(),
		ExternalSecret:   aliceGroup.EpochSecrets.ExternalSecret.Clone(),
		ConfirmationKey:  aliceGroup.EpochSecrets.ConfirmationKey.Clone(),
		MembershipKey:    aliceGroup.EpochSecrets.MembershipKey.Clone(),
		ResumptionSecret: aliceGroup.EpochSecrets.ResumptionSecret.Clone(),
	}"""

content = content.replace(old_code, new_code)

with open('group/integration_test.go', 'w') as f:
    f.write(content)
