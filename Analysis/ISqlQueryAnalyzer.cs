namespace TrinoSqlEngine.Analysis;

using System;
using System.Collections.Generic;

public enum SqlStatementType
{
    Select,
    Insert,
    Update,
    Delete,
    Ddl,
    Other
}

public readonly record struct TableAccessTarget(
    string? Catalog,
    string? Schema,
    string TableName,
    string? Alias,
    string FullName);

public sealed record SqlQueryMetadata(
    SqlStatementType StatementType,
    IReadOnlyList<TableAccessTarget> ReferencedTables,
    IReadOnlyList<string> ProjectedColumns,
    int JoinCount,
    int MaxSubqueryDepth,
    bool HasExplicitLimit,
    long? ExplicitLimitValue);

public interface ISqlQueryAnalyzer
{
    SqlQueryMetadata Analyze(SqlBaseParser.SingleStatementContext statementContext);
}
