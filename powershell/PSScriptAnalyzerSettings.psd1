@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        # The module returns objects; host formatting belongs to the caller.
        'PSAvoidUsingWriteHost'
    )
}
