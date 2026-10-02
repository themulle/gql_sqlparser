namespace TrinoSqlEngine.Analysis;

using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using Antlr4.Runtime.Tree;

public sealed record ExtractedParameter(
    string Name,
    string Token,
    string? TargetColumn = null,
    string? TargetTable = null,
    string? ComparisonOperator = null,
    int FirstPosition = 0);

public sealed class SqlParameterExtractor : SqlBaseBaseListener
{
    private static readonly Regex ParameterRegex = new(
        @"(?:@([a-zA-Z_][a-zA-Z0-9_]*))|(?:\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\})",
        RegexOptions.Compiled,
        TimeSpan.FromMilliseconds(100));

    private static readonly Regex SqlCommentRegex = new(
        @"(?:--[^\r\n]*)|(?:\/\*[\s\S]*?\*\/)",
        RegexOptions.Compiled,
        TimeSpan.FromMilliseconds(100));

    private readonly Dictionary<string, ExtractedParameter> _parameters = new(StringComparer.OrdinalIgnoreCase);

    public IReadOnlyList<ExtractedParameter> ExtractedParameters => new List<ExtractedParameter>(_parameters.Values);

    public static string StripComments(string sql)
    {
        return string.IsNullOrWhiteSpace(sql) ? string.Empty : SqlCommentRegex.Replace(sql, string.Empty);
    }

    /// <summary>
    /// Fast extraction of parameter tokens (@param and {{param}}) from raw SQL text, ignoring comments.
    /// </summary>
    public static IReadOnlyList<ExtractedParameter> ExtractTokens(string rawSql)
    {
        if (string.IsNullOrWhiteSpace(rawSql))
        {
            return [];
        }

        string cleanSql = StripComments(rawSql);
        var results = new Dictionary<string, ExtractedParameter>(StringComparer.OrdinalIgnoreCase);
        var matches = ParameterRegex.Matches(cleanSql);

        foreach (Match match in matches)
        {
            string name = !string.IsNullOrEmpty(match.Groups[1].Value)
                ? match.Groups[1].Value
                : match.Groups[2].Value;

            string token = match.Value;

            if (!results.ContainsKey(name))
            {
                results[name] = new ExtractedParameter(
                    Name: name,
                    Token: token,
                    FirstPosition: match.Index);
            }
        }

        return new List<ExtractedParameter>(results.Values);
    }

    /// <summary>
    /// Normalizes raw SQL containing @param or {{param}} into AST-compliant identifiers __param_{name}.
    /// </summary>
    public static string NormalizeForAst(string rawSql)
    {
        if (string.IsNullOrWhiteSpace(rawSql))
        {
            return string.Empty;
        }

        string cleanSql = StripComments(rawSql);
        string trimmed = cleanSql.Trim().TrimEnd(';');
        return ParameterRegex.Replace(trimmed, match =>
        {
            string name = !string.IsNullOrEmpty(match.Groups[1].Value)
                ? match.Groups[1].Value
                : match.Groups[2].Value;
            return $"__param_{name}";
        });
    }

    /// <summary>
    /// Analyzes an AST statement and enriches extracted parameters with contextual target column and operator.
    /// </summary>
    public static IReadOnlyList<ExtractedParameter> AnalyzeAstParameters(
        SqlBaseParser.SingleStatementContext statementContext,
        IReadOnlyList<ExtractedParameter> initialParams)
    {
        ArgumentNullException.ThrowIfNull(statementContext);
        ArgumentNullException.ThrowIfNull(initialParams);

        var extractor = new SqlParameterExtractor();
        foreach (var p in initialParams)
        {
            extractor._parameters[p.Name] = p;
        }

        ParseTreeWalker.Default.Walk(extractor, statementContext);
        return extractor.ExtractedParameters;
    }

    public override void EnterComparison(SqlBaseParser.ComparisonContext context)
    {
        var op = context.comparisonOperator();
        string opText = op?.GetText() ?? "=";

        var leftCtx = context.value ?? (context.Parent as SqlBaseParser.PredicatedContext)?.valueExpression();
        var rightCtx = context.right ?? context.valueExpression();

        if (leftCtx == null || rightCtx == null) return;

        string leftText = leftCtx.GetText();
        string rightText = rightCtx.GetText();

        CheckAndAssociate(leftText, rightText, opText);
        CheckAndAssociate(rightText, leftText, opText);
    }

    private void CheckAndAssociate(string possibleColText, string possibleParamText, string opText)
    {
        if (possibleParamText.StartsWith("__param_", StringComparison.OrdinalIgnoreCase))
        {
            string paramName = possibleParamText["__param_".Length..];
            if (_parameters.TryGetValue(paramName, out var existing))
            {
                string normCol = SqlIdentifierHelper.NormalizeIdentifier(possibleColText);
                string? targetTable = null;
                string targetCol = normCol;

                int dotIdx = normCol.LastIndexOf('.');
                if (dotIdx > 0)
                {
                    targetTable = normCol[..dotIdx];
                    targetCol = normCol[(dotIdx + 1)..];
                }

                _parameters[paramName] = existing with
                {
                    TargetColumn = targetCol,
                    TargetTable = targetTable,
                    ComparisonOperator = opText
                };
            }
        }
    }
}
