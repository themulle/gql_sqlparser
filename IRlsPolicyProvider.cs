namespace TrinoSqlEngine;

using System;

public interface IRlsPolicyProvider
{
    bool ShouldApplyPolicy(string tableName);
    string GetPolicyFilter(string tableName);
}

public sealed class DefaultRlsPolicyProvider : IRlsPolicyProvider
{
    private readonly string _defaultFilter;
    private readonly Func<string, bool>? _predicate;
    private readonly Func<string, string>? _filterFunc;

    public DefaultRlsPolicyProvider(
        string defaultFilter = "tenant_id = 42", 
        Func<string, bool>? predicate = null,
        Func<string, string>? filterFunc = null)
    {
        _defaultFilter = defaultFilter ?? throw new ArgumentNullException(nameof(defaultFilter));
        _predicate = predicate;
        _filterFunc = filterFunc;
    }

    public bool ShouldApplyPolicy(string tableName)
    {
        if (_predicate == null) return true;
        if (_predicate(tableName)) return true;

        // If tableName is qualified e.g. "my_schema.orders", also test unqualified simple name "orders"
        int lastDot = tableName.LastIndexOf('.');
        if (lastDot >= 0 && lastDot < tableName.Length - 1)
        {
            string simpleName = tableName.Substring(lastDot + 1);
            if (_predicate(simpleName)) return true;
        }

        return false;
    }

    public string GetPolicyFilter(string tableName)
    {
        if (_filterFunc != null) return _filterFunc(tableName);
        return _defaultFilter;
    }
}

public sealed class RlsOptions
{
    /// <summary>
    /// Policy provider that determines whether and how a table is filtered.
    /// </summary>
    public IRlsPolicyProvider PolicyProvider { get; set; } = new DefaultRlsPolicyProvider();

    /// <summary>
    /// SEC-01: When true, throws an exception if non-SELECT statements (INSERT, UPDATE, DELETE, DDL) are passed to the RLS rewriter.
    /// Default is true to maintain maximum security by default. Set to false to enable DML rewriting (UPDATE, DELETE, INSERT).
    /// </summary>
    public bool EnforceReadOnlyQueries { get; set; } = true;

    /// <summary>
    /// SEC-02: When true, automatically appends "AS {tableName}" if the rewritten subquery does not already have an alias.
    /// Default is false to maintain backward-compatibility with step-8 simple rewrite format.
    /// </summary>
    public bool AppendTableAlias { get; set; } = false;

    /// <summary>
    /// When true, validates INSERT and UPDATE statements against WITH CHECK OPTION to prevent tenant-hopping and trojan records.
    /// </summary>
    public bool EnforceWithCheckOption { get; set; } = true;

    /// <summary>
    /// The name of the tenant isolation column. Default is "tenant_id".
    /// </summary>
    public string TenantColumnName { get; set; } = "tenant_id";

    /// <summary>
    /// Expected tenant value for WITH CHECK OPTION verification. Default is "42".
    /// </summary>
    public string ExpectedTenantValue { get; set; } = "42";

    /// <summary>
    /// If true, strictly forbids setting the tenant column in an UPDATE statement regardless of the assigned value.
    /// </summary>
    public bool DisallowTenantColumnModificationInUpdate { get; set; } = true;

    /// <summary>
    /// When true and EnforceWithCheckOption is true, requires INSERT statements to explicitly specify the tenant column.
    /// Default is false to allow databases with DEFAULT tenant expressions.
    /// </summary>
    public bool RequireTenantColumnInInsert { get; set; } = false;
}
