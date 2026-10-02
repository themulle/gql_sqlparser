namespace TrinoSqlEngine;

using System;
using System.Collections.Frozen;
using System.Collections.Generic;

/// <summary>
/// SEC C-01: Function policy for SQL ASTs. Scalar/aggregate functions are not covered by table-based
/// RLS, masking or ABAC. Functions that accept SQL text or table names, read server files, open remote
/// connections or change session state are therefore rejected by default.
/// </summary>
public static class SqlFunctionPolicy
{
    /// <summary>
    /// Function names (lower case, unqualified) that are rejected by default.
    /// </summary>
    public static readonly IReadOnlySet<string> DefaultDeniedFunctions = new[]
    {
        // PostgreSQL: SQL text / table name to XML (full table dumps bypassing RLS)
        "query_to_xml", "query_to_xml_and_xmlschema", "query_to_xmlschema",
        "table_to_xml", "table_to_xml_and_xmlschema", "table_to_xmlschema",
        "cursor_to_xml", "cursor_to_xmlschema",
        "database_to_xml", "database_to_xml_and_xmlschema", "database_to_xmlschema",
        "schema_to_xml", "schema_to_xml_and_xmlschema", "schema_to_xmlschema",
        // PostgreSQL: server file system / large objects
        "pg_read_file", "pg_read_binary_file", "pg_ls_dir", "pg_stat_file",
        "lo_import", "lo_export", "lo_get", "lo_put", "lo_from_bytea", "lo_open", "lo_unlink",
        // PostgreSQL: remote connections
        "dblink", "dblink_exec", "dblink_connect", "dblink_connect_u", "dblink_send_query", "dblink_open", "dblink_fetch",
        // PostgreSQL: session state, configuration, process control, notifications, server info (SQ-06)
        "set_config", "current_setting", "pg_sleep", "pg_sleep_for", "pg_sleep_until",
        "pg_terminate_backend", "pg_cancel_backend", "pg_reload_conf", "pg_rotate_logfile",
        "pg_promote", "pg_switch_wal", "pg_create_restore_point", "pg_backend_pid",
        "pg_advisory_lock", "pg_advisory_xact_lock", "pg_try_advisory_lock",
        "pg_logical_emit_message", "pg_file_write", "pg_file_rename", "pg_file_unlink",
        "pg_notify", "pg_current_logfile", "pg_export_snapshot", "pg_stat_reset",
        "pg_log_backend_memory_contexts", "inet_server_addr", "version", "txid_current",
        // SQL Server (SQ-06)
        "xp_cmdshell", "openrowset", "openquery", "opendatasource", "openxml", "sp_executesql",
        "exec", "execute", "fn_dblog", "fn_xe_file_target_read_file", "fn_get_audit_file", "fn_trace_gettable",
        "has_dbaccess", "suser_sname", "is_srvrolemember", "suser_name", "suser_id", "is_member",
        // MySQL / MariaDB / UDF-based command execution
        "load_file", "sys_exec", "sys_eval", "benchmark", "sleep",
        // Oracle
        "dbms_xmlgen", "dbms_sql", "utl_http", "utl_file", "utl_inaddr", "httpuritype",
    }.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Function name prefixes (lower case, unqualified) that are rejected by default.
    /// </summary>
    public static readonly IReadOnlyList<string> DefaultDeniedPrefixes = new[]
    {
        "query_to_xml", "table_to_xml", "cursor_to_xml", "database_to_xml", "schema_to_xml",
        "pg_read_", "pg_ls_", "pg_stat_file", "pg_file_", "pg_terminate_", "pg_cancel_",
        "pg_advisory_", "pg_try_advisory_", "pg_sleep", "pg_get_", "pg_stat_", "pg_replication_",
        "lo_", "dblink", "xp_", "sp_", "dbms_", "utl_", "fn_dblog", "fn_xe_", "fn_get_audit_", "fn_trace_",
    };

    /// <summary>
    /// Returns true when the (possibly qualified) function name is on the default denylist.
    /// The full name and the last name segment are both checked.
    /// </summary>
    public static bool IsDeniedByDefault(string functionName)
    {
        if (string.IsNullOrWhiteSpace(functionName)) return false;

        string full = functionName.Trim().ToLowerInvariant();
        string simple = GetSimpleName(full);

        if (DefaultDeniedFunctions.Contains(full) || DefaultDeniedFunctions.Contains(simple))
            return true;

        foreach (var prefix in DefaultDeniedPrefixes)
        {
            if (simple.StartsWith(prefix, StringComparison.Ordinal))
                return true;
        }

        return false;
    }

    /// <summary>
    /// Evaluates a function call against the configured policy.
    /// Order: additional denylist (always wins) -> explicit allowlist (if configured, exclusive) -> default denylist.
    /// </summary>
    public static bool IsFunctionAllowed(string functionName, RlsOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrWhiteSpace(functionName)) return false;

        string full = functionName.Trim().ToLowerInvariant();
        string simple = GetSimpleName(full);

        if (options.AdditionalDeniedFunctions != null &&
            (ContainsIgnoreCase(options.AdditionalDeniedFunctions, full) || ContainsIgnoreCase(options.AdditionalDeniedFunctions, simple)))
        {
            return false;
        }

        if (options.AllowedFunctions != null)
        {
            // Allowlist mode: exact (qualified) name match only.
            return ContainsIgnoreCase(options.AllowedFunctions, full);
        }

        return !IsDeniedByDefault(full);
    }

    internal static bool ContainsIgnoreCase(IReadOnlySet<string> set, string value)
    {
        if (set.Contains(value)) return true;
        foreach (var entry in set)
        {
            if (string.Equals(entry, value, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private static string GetSimpleName(string fullName)
    {
        int lastDot = fullName.LastIndexOf('.');
        return lastDot >= 0 && lastDot < fullName.Length - 1 ? fullName[(lastDot + 1)..] : fullName;
    }
}
