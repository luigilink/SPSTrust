@{
    # Settings consumed by Invoke-ScriptAnalyzer in CI and the local lint task.
    #
    # PSUseShouldProcessForStateChangingFunctions is excluded because the public
    # Set-*/New-*/Remove-*/Publish-* functions are thin wrappers that marshal a
    # script block to a remote farm through Invoke-SPSCommand (CredSSP). Their
    # create/remove behaviour is already driven explicitly by an -Ensure parameter,
    # and the destructive path is gated at the entry-script level by the
    # -CleanServices switch. Adding SupportsShouldProcess/ShouldProcess plumbing to
    # each remoting wrapper would add no real safety and is inconsistent with the
    # rest of the SPS* toolkit. The rule is therefore excluded project-wide.
    ExcludeRules = @(
        'PSUseShouldProcessForStateChangingFunctions'
    )
}
