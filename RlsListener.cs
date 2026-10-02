namespace TrinoSqlEngine;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using Antlr4.Runtime;
using Antlr4.Runtime.Tree;

public static class SqlIdentifierHelper
{
    public static string NormalizeIdentifier(string id)
    {
        if (string.IsNullOrWhiteSpace(id)) return string.Empty;
        id = id.Trim();
        if (id.Length >= 2)
        {
            if ((id[0] == '"' && id[^1] == '"') ||
                (id[0] == '`' && id[^1] == '`') ||
                (id[0] == '[' && id[^1] == ']'))
            {
                return id[1..^1];
            }
        }
        return id;
    }

    /// <summary>
    /// SEC C-02: Scope key for single-part identifiers (CTE names). Unquoted identifiers are case-folded to lower case,
    /// quoted identifiers keep their exact content (doubled quote characters are unescaped). Comparing keys ordinally
    /// is therefore conservative for both case-insensitive (Trino) and case-sensitive quoted (PostgreSQL) semantics:
    /// when in doubt a reference is treated as a physical table (and secured), never as a CTE.
    /// </summary>
    public static string FoldIdentifierForScope(string rawIdentifier)
    {
        if (string.IsNullOrWhiteSpace(rawIdentifier)) return string.Empty;
        string id = rawIdentifier.Trim();
        if (id.Length >= 2)
        {
            char first = id[0];
            char last = id[^1];
            if (first == '"' && last == '"') return id[1..^1].Replace("\"\"", "\"", StringComparison.Ordinal);
            if (first == '`' && last == '`') return id[1..^1].Replace("``", "`", StringComparison.Ordinal);
            if (first == '[' && last == ']') return id[1..^1];
        }
        return id.ToLowerInvariant();
    }

    /// <summary>
    /// SEC M-24: Quotes a catalog-provided column name as a delimited SQL identifier ("..." with doubled quotes).
    /// </summary>
    public static string QuoteIdentifier(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        return "\"" + name.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
    }

    /// <summary>
    /// SEC M-23: Removes exactly one pair of enclosing single quotes and unescapes doubled quotes ('' -> ').
    /// Values without enclosing single quotes are returned trimmed but otherwise unchanged.
    /// </summary>
    public static string UnquoteStringLiteral(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        string v = value.Trim();
        if (v.Length >= 2 && v[0] == '\'' && v[^1] == '\'')
        {
            return v[1..^1].Replace("''", "'", StringComparison.Ordinal);
        }
        return v;
    }

    public static string NormalizeQualifiedName(SqlBaseParser.QualifiedNameContext context)
    {
        var ids = context.identifier();
        if (ids == null || ids.Length == 0) return NormalizeIdentifier(context.GetText());
        var parts = new string[ids.Length];
        for (int i = 0; i < ids.Length; i++)
        {
            parts[i] = NormalizeIdentifier(ids[i].GetText());
        }
        return string.Join(".", parts);
    }
}

public sealed class RlsListener : SqlBaseBaseListener
{
    private readonly TokenStreamRewriter _rewriter;
    private readonly RlsOptions _options;
    private readonly Stack<HashSet<string>> _cteScopeStack = new();
    private bool _rootLimitHandled = false;

    public RlsListener(ITokenStream tokens, RlsOptions? options = null)
    {
        _rewriter = new TokenStreamRewriter(tokens);
        _options = options ?? new RlsOptions();
        _cteScopeStack.Push(new HashSet<string>(StringComparer.Ordinal));
    }

    // SEC-01: Statement validation based on EnforceReadOnlyQueries
    public override void EnterSingleStatement(SqlBaseParser.SingleStatementContext context)
    {
        var stmt = context.statement();
        if (stmt == null) return;

        if (_options.EnforceReadOnlyQueries)
        {
            if (stmt is not SqlBaseParser.StatementDefaultContext)
            {
                throw new SecurityException($"RLS rewriter only allows read-only SELECT statements. Rejected: {stmt.GetType().Name}");
            }
        }
        else
        {
            // When EnforceReadOnlyQueries is false, allow SELECT, DELETE, UPDATE, and INSERT INTO.
            // Reject any administrative DDL (DROP, CREATE, ALTER, TRUNCATE, GRANT, REVOKE, CALL, MERGE, etc.).
            if (stmt is not SqlBaseParser.StatementDefaultContext &&
                stmt is not SqlBaseParser.DeleteContext &&
                stmt is not SqlBaseParser.UpdateContext &&
                stmt is not SqlBaseParser.InsertIntoContext)
            {
                throw new SecurityException($"Unsupported or unsafe statement type for RLS rewriting: {stmt.GetType().Name}");
            }
        }
    }

    // SEC H-14: WITH SESSION is rejected unless every property is allowlisted.
    public override void EnterRootQueryWithSession(SqlBaseParser.RootQueryWithSessionContext context)
    {
        var properties = context.sessionProperty();
        if (properties == null || properties.Length == 0) return;

        foreach (var property in properties)
        {
            string name = SqlIdentifierHelper.NormalizeQualifiedName(property.qualifiedName());
            if (_options.AllowedSessionProperties == null ||
                !SqlFunctionPolicy.ContainsIgnoreCase(_options.AllowedSessionProperties, name))
            {
                throw new SecurityException($"WITH SESSION property '{name}' is not permitted.");
            }
        }
    }

    // SEC H-14: Inline function definitions (WITH FUNCTION ...) are rejected by default.
    public override void EnterRootQuery(SqlBaseParser.RootQueryContext context)
    {
        var functions = context.functionSpecification();
        if (functions != null && functions.Length > 0 && !_options.AllowInlineFunctionDefinitions)
        {
            throw new SecurityException("Inline function definitions (WITH FUNCTION) are not permitted.");
        }
    }

    // SEC H-14: Table functions (TABLE(fn(...))) may execute raw SQL on the connector; allowlist only.
    public override void EnterTableFunctionInvocation(SqlBaseParser.TableFunctionInvocationContext context)
    {
        string name = SqlIdentifierHelper.NormalizeQualifiedName(context.tableFunctionCall().qualifiedName());
        if (_options.AllowedTableFunctions == null ||
            !SqlFunctionPolicy.ContainsIgnoreCase(_options.AllowedTableFunctions, name))
        {
            throw new SecurityException($"Table function '{name}' is not permitted.");
        }
    }

    // SEC C-01: Function policy (denylist / optional allowlist).
    public override void EnterFunctionCall(SqlBaseParser.FunctionCallContext context)
    {
        if (!_options.EnforceFunctionPolicy) return;

        string name = SqlIdentifierHelper.NormalizeQualifiedName(context.qualifiedName());
        if (!SqlFunctionPolicy.IsFunctionAllowed(name, _options))
        {
            throw new SecurityException($"Function '{name}' is not permitted by the SQL function policy.");
        }
    }

    // SEC-05: Lexical CTE Scoping
    public override void EnterQuery(SqlBaseParser.QueryContext context)
    {
        _cteScopeStack.Push(new HashSet<string>(_cteScopeStack.Peek(), StringComparer.Ordinal));
    }

    public override void ExitQuery(SqlBaseParser.QueryContext context)
    {
        if (_cteScopeStack.Count > 1)
        {
            _cteScopeStack.Pop();
        }
    }

    // SEC-CTE: Add CTE name to scope on EXIT, NOT on enter.
    // In SQL standard, a CTE query cannot reference itself unless recursive, and shadowing
    // a physical table must NOT bypass physical table RLS filters inside the CTE definition.
    // SEC C-02: CTE names are single-part identifiers; stored as folded scope key, never as dotted string.
    public override void ExitNamedQuery(SqlBaseParser.NamedQueryContext context)
    {
        string cteKey = SqlIdentifierHelper.FoldIdentifierForScope(context.name.GetText());
        _cteScopeStack.Peek().Add(cteKey);
    }

    /// <summary>
    /// SEC M-22: The enforced LIMIT belongs to the root queryNoWith of a read statement only
    /// (statementDefault -> rootQueryWithSession -> rootQuery -> query -> queryNoWith).
    /// CTE bodies, IN/EXISTS/scalar subqueries and derived tables can no longer consume it.
    /// </summary>
    private static bool IsRootReadQueryNoWith(SqlBaseParser.QueryNoWithContext context)
    {
        return context.Parent is SqlBaseParser.QueryContext query &&
               query.Parent is SqlBaseParser.RootQueryContext rootQuery &&
               rootQuery.Parent is SqlBaseParser.RootQueryWithSessionContext rootWithSession &&
               rootWithSession.Parent is SqlBaseParser.StatementDefaultContext;
    }

    public override void EnterQueryNoWith(SqlBaseParser.QueryNoWithContext context)
    {
        if (_options.EnforcedMaxRows <= 0 || _rootLimitHandled || !IsRootReadQueryNoWith(context))
            return;

        string maxRows = _options.EnforcedMaxRows.ToString(System.Globalization.CultureInfo.InvariantCulture);

        if (context.limit != null)
        {
            _rootLimitHandled = true;
            var rowCount = context.limit.rowCount();
            if (rowCount != null)
            {
                if (!long.TryParse(rowCount.GetText(), out long existingVal) || existingVal > _options.EnforcedMaxRows)
                {
                    _rewriter.Replace(rowCount.Start, rowCount.Stop, maxRows);
                }
            }
            else if (context.limit.ALL() != null)
            {
                _rewriter.Replace(context.limit.ALL().Symbol, maxRows);
            }
        }
        else if (context.FETCH() != null)
        {
            _rootLimitHandled = true;
            if (context.fetchFirst != null)
            {
                if (!long.TryParse(context.fetchFirst.GetText(), out long existingVal) || existingVal > _options.EnforcedMaxRows)
                {
                    _rewriter.Replace(context.fetchFirst.Start, context.fetchFirst.Stop, maxRows);
                }
            }

            // WITH TIES may return more rows than requested; downgrade to ONLY.
            if (context.TIES() != null && context.WITH() != null)
            {
                _rewriter.Replace(context.WITH().Symbol, context.TIES().Symbol, "ONLY");
            }
        }
    }

    public override void ExitQueryNoWith(SqlBaseParser.QueryNoWithContext context)
    {
        if (_options.EnforcedMaxRows > 0 && !_rootLimitHandled && IsRootReadQueryNoWith(context))
        {
            _rootLimitHandled = true;
            _rewriter.InsertAfter(context.Stop, $" LIMIT {_options.EnforcedMaxRows.ToString(System.Globalization.CultureInfo.InvariantCulture)}");
        }
    }

    // Standard SELECT relation: FROM orders (relationPrimary: qualifiedName -> #tableName)
    public override void EnterTableName(SqlBaseParser.TableNameContext context)
    {
        string rawName = context.qualifiedName().GetText();
        string normalizedName = SqlIdentifierHelper.NormalizeQualifiedName(context.qualifiedName());

        if (IsCte(context.qualifiedName()))
            return;

        bool shouldApplyRls = _options.PolicyProvider.ShouldApplyPolicy(normalizedName);
        bool hasMasking = HasMaskingForTable(normalizedName);

        if (!shouldApplyRls && !hasMasking)
            return;

        string replacement = BuildReplacement(context, rawName, normalizedName, shouldApplyRls);
        _rewriter.Replace(context.Start, context.Stop, replacement);
    }

    // Trino/SQL 'TABLE orders' Syntax (queryPrimary -> #table)
    public override void EnterTable(SqlBaseParser.TableContext context)
    {
        string rawName = context.qualifiedName().GetText();
        string normalizedName = SqlIdentifierHelper.NormalizeQualifiedName(context.qualifiedName());

        if (IsCte(context.qualifiedName()))
            return;

        bool shouldApplyRls = _options.PolicyProvider.ShouldApplyPolicy(normalizedName);
        bool hasMasking = HasMaskingForTable(normalizedName);

        if (!shouldApplyRls && !hasMasking)
            return;

        string replacement = BuildReplacement(context, rawName, normalizedName, shouldApplyRls);
        _rewriter.Replace(context.Start, context.Stop, replacement);
    }

    // Trino Polymorphic Table Functions: TABLE(orders) argument (tableArgumentRelation -> #tableArgumentTable)
    public override void EnterTableArgumentTable(SqlBaseParser.TableArgumentTableContext context)
    {
        string rawName = context.qualifiedName().GetText();
        string normalizedName = SqlIdentifierHelper.NormalizeQualifiedName(context.qualifiedName());

        if (IsCte(context.qualifiedName()))
            return;

        bool shouldApplyRls = _options.PolicyProvider.ShouldApplyPolicy(normalizedName);
        bool hasMasking = HasMaskingForTable(normalizedName);

        if (!shouldApplyRls && !hasMasking)
            return;

        string replacement = BuildReplacement(context, rawName, normalizedName, shouldApplyRls);
        _rewriter.Replace(context.qualifiedName().Start, context.qualifiedName().Stop, replacement);
    }

    // DML: DELETE FROM <table> [WHERE <predicate>]
    public override void EnterDelete(SqlBaseParser.DeleteContext context)
    {
        string normalizedName = SqlIdentifierHelper.NormalizeQualifiedName(context.qualifiedName());

        // SEC H-15: masked columns must not be usable as row-count oracle in WHERE.
        if (context.booleanExpression() != null)
        {
            EnsureNoMaskedColumnReferences(normalizedName, context.booleanExpression(), "DELETE WHERE");
        }

        // DML guardrail: checked on the original statement (the parse tree is not affected by the RLS rewrite).
        EnsureFilteredDml(context.booleanExpression(), "DELETE");

        if (IsCte(context.qualifiedName()) || !_options.PolicyProvider.ShouldApplyPolicy(normalizedName))
            return;

        string policyFilter = _options.PolicyProvider.GetPolicyFilter(normalizedName);

        if (context.booleanExpression() != null)
        {
            _rewriter.InsertBefore(context.booleanExpression().Start, $"({policyFilter}) AND (");
            _rewriter.InsertAfter(context.booleanExpression().Stop, ")");
        }
        else
        {
            _rewriter.InsertAfter(context.Stop, $" WHERE ({policyFilter})");
        }
    }

    // DML: UPDATE <table> SET <assignments> [WHERE <predicate>]
    public override void EnterUpdate(SqlBaseParser.UpdateContext context)
    {
        string normalizedName = SqlIdentifierHelper.NormalizeQualifiedName(context.qualifiedName());
        var assignments = context.updateAssignment();

        // SEC H-15: masked columns must neither be written/copied in SET nor probed in WHERE.
        if (assignments != null)
        {
            foreach (var assignment in assignments)
            {
                EnsureNoMaskedColumnReferences(normalizedName, assignment, "UPDATE SET");
            }
        }
        if (context.where != null)
        {
            EnsureNoMaskedColumnReferences(normalizedName, context.where, "UPDATE WHERE");
        }

        // DML guardrail: checked on the original statement (the parse tree is not affected by the RLS rewrite).
        EnsureFilteredDml(context.where, "UPDATE");

        // 1. WITH CHECK OPTION verification on assignments
        if (_options.EnforceWithCheckOption && assignments != null)
        {
            string expectedTenant = SqlIdentifierHelper.UnquoteStringLiteral(_options.ExpectedTenantValue);

            foreach (var assignment in assignments)
            {
                string colName = SqlIdentifierHelper.NormalizeIdentifier(assignment.identifier().GetText());
                if (colName.Equals(_options.TenantColumnName, StringComparison.OrdinalIgnoreCase))
                {
                    if (_options.DisallowTenantColumnModificationInUpdate)
                    {
                        throw new SecurityException($"Modification of tenant column '{colName}' is not allowed in UPDATE statement.");
                    }

                    EnsureTenantLiteral(assignment.expression(), expectedTenant, "UPDATE");
                }
            }
        }

        // 2. WHERE clause injection
        if (IsCte(context.qualifiedName()) || !_options.PolicyProvider.ShouldApplyPolicy(normalizedName))
            return;

        string policyFilter = _options.PolicyProvider.GetPolicyFilter(normalizedName);

        if (context.where != null)
        {
            _rewriter.InsertBefore(context.where.Start, $"({policyFilter}) AND (");
            _rewriter.InsertAfter(context.where.Stop, ")");
        }
        else
        {
            _rewriter.InsertAfter(context.Stop, $" WHERE ({policyFilter})");
        }
    }

    // DML: INSERT INTO <table> [(col1, ...)] <query>
    public override void EnterInsertInto(SqlBaseParser.InsertIntoContext context)
    {
        if (!_options.EnforceWithCheckOption)
            return;

        var colAliasesContext = context.columnAliases();
        var idList = colAliasesContext?.identifier();

        int tenantIndex = -1;
        if (idList != null)
        {
            for (int i = 0; i < idList.Length; i++)
            {
                string col = SqlIdentifierHelper.NormalizeIdentifier(idList[i].GetText());
                if (col.Equals(_options.TenantColumnName, StringComparison.OrdinalIgnoreCase))
                {
                    tenantIndex = i;
                    break;
                }
            }
        }

        if (tenantIndex == -1)
        {
            if (_options.RequireTenantColumnInInsert)
            {
                throw new SecurityException($"Tenant column '{_options.TenantColumnName}' must be explicitly specified in INSERT statement.");
            }
            return;
        }

        var queryNoWith = context.rootQuery()?.query()?.queryNoWith();
        if (queryNoWith == null)
        {
            throw new SecurityException("INSERT statement without a verifiable source query is not allowed.");
        }

        // SEC M-23: verify every VALUES row and every branch of set operations; non-literals are rejected.
        string expectedTenant = SqlIdentifierHelper.UnquoteStringLiteral(_options.ExpectedTenantValue);
        VerifyInsertQueryTerm(queryNoWith.queryTerm(), tenantIndex, expectedTenant);
    }

    private void VerifyInsertQueryTerm(SqlBaseParser.QueryTermContext? term, int tenantIndex, string expectedTenant)
    {
        switch (term)
        {
            case SqlBaseParser.SetOperationContext setOperation:
                VerifyInsertQueryTerm(setOperation.left, tenantIndex, expectedTenant);
                VerifyInsertQueryTerm(setOperation.right, tenantIndex, expectedTenant);
                return;
            case SqlBaseParser.QueryTermDefaultContext termDefault:
                VerifyInsertQueryPrimary(termDefault.queryPrimary(), tenantIndex, expectedTenant);
                return;
            default:
                throw new SecurityException("INSERT source query shape cannot be verified against the tenant WITH CHECK OPTION.");
        }
    }

    private void VerifyInsertQueryPrimary(SqlBaseParser.QueryPrimaryContext? primary, int tenantIndex, string expectedTenant)
    {
        switch (primary)
        {
            case SqlBaseParser.InlineTableContext inlineTable:
                {
                    var rows = inlineTable.expression();
                    if (rows == null || rows.Length == 0)
                    {
                        throw new SecurityException("INSERT VALUES clause without rows cannot be verified.");
                    }

                    foreach (var row in rows)
                    {
                        var values = ExtractRowValues(row);
                        if (tenantIndex >= values.Count)
                        {
                            throw new SecurityException($"Tenant column '{_options.TenantColumnName}' has no value in an INSERT VALUES row.");
                        }
                        EnsureTenantLiteral(values[tenantIndex], expectedTenant, "INSERT");
                    }
                    return;
                }
            case SqlBaseParser.QueryPrimaryDefaultContext primaryDefault:
                {
                    var items = primaryDefault.querySpecification().selectItem();
                    if (items == null)
                    {
                        throw new SecurityException("INSERT SELECT without projection cannot be verified.");
                    }

                    // A '*' before or at the tenant position makes the column mapping unverifiable.
                    for (int i = 0; i < items.Length && i <= tenantIndex; i++)
                    {
                        if (items[i] is not SqlBaseParser.SelectSingleContext)
                        {
                            throw new SecurityException($"Tenant column '{_options.TenantColumnName}' in INSERT SELECT cannot be verified (wildcard projection).");
                        }
                    }

                    if (tenantIndex >= items.Length || items[tenantIndex] is not SqlBaseParser.SelectSingleContext single || single.expression() == null)
                    {
                        throw new SecurityException($"Tenant column '{_options.TenantColumnName}' has no value in INSERT SELECT.");
                    }

                    EnsureTenantLiteral(single.expression(), expectedTenant, "INSERT SELECT");
                    return;
                }
            case SqlBaseParser.SubqueryContext subquery:
                VerifyInsertQueryTerm(subquery.queryNoWith()?.queryTerm(), tenantIndex, expectedTenant);
                return;
            default:
                throw new SecurityException("INSERT source query shape cannot be verified against the tenant WITH CHECK OPTION.");
        }
    }

    private void EnsureTenantLiteral(SqlBaseParser.ExpressionContext? expr, string expectedTenant, string operation)
    {
        string? literal = TryGetLiteralValue(expr);
        if (literal == null)
        {
            throw new SecurityException($"Tenant column '{_options.TenantColumnName}' in {operation} must be a literal value.");
        }

        if (!literal.Equals(expectedTenant, StringComparison.Ordinal))
        {
            throw new SecurityException($"Tenant column '{_options.TenantColumnName}' {operation} value '{literal}' does not match expected tenant '{expectedTenant}'.");
        }
    }

    /// <summary>
    /// SEC M-23: Returns the value of a plain string or unsigned integer/decimal literal (optionally parenthesized), otherwise null.
    /// </summary>
    private static string? TryGetLiteralValue(SqlBaseParser.ExpressionContext? expr)
    {
        var primary = UnwrapPrimary(expr);
        if (primary is not SqlBaseParser.LiteralsContext literals)
            return null;

        var literal = literals.literal();
        if (literal == null || literal.Start == null || literal.Start.TokenIndex != literal.Stop?.TokenIndex)
            return null;

        int tokenType = literal.Start.Type;
        if (literal is SqlBaseParser.StringLiteralContext && tokenType == SqlBaseLexer.STRING)
        {
            return SqlIdentifierHelper.UnquoteStringLiteral(literal.Start.Text);
        }

        if (literal is SqlBaseParser.NumericLiteralContext &&
            (tokenType == SqlBaseLexer.INTEGER_VALUE || tokenType == SqlBaseLexer.DECIMAL_VALUE))
        {
            return literal.Start.Text;
        }

        return null;
    }

    private static SqlBaseParser.PrimaryExpressionContext? UnwrapPrimary(SqlBaseParser.ExpressionContext? expr)
    {
        while (expr != null)
        {
            if (expr.booleanExpression() is not SqlBaseParser.PredicatedContext predicated || predicated.predicate() != null)
                return null;
            if (predicated.valueExpression() is not SqlBaseParser.ValueExpressionDefaultContext valueDefault)
                return null;

            var primary = valueDefault.primaryExpression();
            if (primary is SqlBaseParser.ParenthesizedExpressionContext parenthesized)
            {
                expr = parenthesized.expression();
                continue;
            }
            return primary;
        }
        return null;
    }

    private static IReadOnlyList<SqlBaseParser.ExpressionContext> ExtractRowValues(SqlBaseParser.ExpressionContext rowExpr)
    {
        var primary = UnwrapPrimary(rowExpr);
        if (primary is SqlBaseParser.RowConstructorContext row)
        {
            var exprs = row.expression();
            if (exprs != null && exprs.Length > 0)
                return exprs;

            var fields = row.fieldConstructor();
            if (fields != null && fields.Length > 0)
            {
                var list = new List<SqlBaseParser.ExpressionContext>(fields.Length);
                foreach (var f in fields)
                {
                    list.Add(f.expression());
                }
                return list;
            }
        }

        return new[] { rowExpr };
    }

    /// <summary>
    /// DML guardrail (<see cref="RlsOptions.RejectUnfilteredDml"/>): UPDATE/DELETE must carry a WHERE clause that is not
    /// trivially true. Only simple, syntactically obvious tautologies are detected (TRUE literal, comparison of equal
    /// constants, a column compared with itself, NOT FALSE, constant IS NOT NULL, combined via AND/OR/parentheses).
    /// </summary>
    private void EnsureFilteredDml(SqlBaseParser.BooleanExpressionContext? where, string operation)
    {
        if (!_options.RejectUnfilteredDml)
            return;

        if (where == null)
        {
            throw new UnfilteredDmlException($"{operation} without a WHERE clause is not permitted.");
        }

        if (IsTriviallyTrue(where))
        {
            throw new UnfilteredDmlException($"{operation} with a trivially true WHERE clause is not permitted.");
        }
    }

    private static bool IsTriviallyTrue(SqlBaseParser.BooleanExpressionContext? expr)
    {
        switch (expr)
        {
            case SqlBaseParser.OrContext orExpr:
                {
                    var parts = orExpr.booleanExpression();
                    foreach (var part in parts)
                    {
                        if (IsTriviallyTrue(part))
                            return true;
                    }
                    return false;
                }
            case SqlBaseParser.AndContext andExpr:
                {
                    var parts = andExpr.booleanExpression();
                    if (parts.Length == 0)
                        return false;
                    foreach (var part in parts)
                    {
                        if (!IsTriviallyTrue(part))
                            return false;
                    }
                    return true;
                }
            case SqlBaseParser.LogicalNotContext notExpr:
                return IsBooleanConstant(notExpr.booleanExpression(), expected: false);
            case SqlBaseParser.PredicatedContext predicated:
                return IsTriviallyTruePredicated(predicated);
            default:
                return false;
        }
    }

    private static bool IsTriviallyTruePredicated(SqlBaseParser.PredicatedContext predicated)
    {
        var left = predicated.valueExpression();
        var predicate = predicated.predicate();

        if (predicate == null)
        {
            var nested = TryGetParenthesizedBoolean(left);
            if (nested != null)
                return IsTriviallyTrue(nested);

            return TryGetConstant(left, out var kind, out var text) && kind == 'b' &&
                   text.Equals("true", StringComparison.OrdinalIgnoreCase);
        }

        if (predicate is SqlBaseParser.ComparisonContext comparison)
        {
            var op = comparison.comparisonOperator();
            if (op == null || left == null || comparison.right == null)
                return false;

            bool isEqualityLike = op.EQ() != null || op.LTE() != null || op.GTE() != null;

            if (TryGetConstant(left, out var leftKind, out var leftText) &&
                TryGetConstant(comparison.right, out var rightKind, out var rightText))
            {
                bool equal = ConstantsEqual(leftKind, leftText, rightKind, rightText);
                if (isEqualityLike)
                    return equal;
                if (op.NEQ() != null)
                    return leftKind == rightKind && !equal;
                return false;
            }

            // A column compared with itself (id = id) matches every non-NULL row.
            if (isEqualityLike && IsSameColumnReference(left, comparison.right))
                return true;

            return false;
        }

        if (predicate is SqlBaseParser.NullPredicateContext nullPredicate)
        {
            return nullPredicate.NOT() != null &&
                   TryGetConstant(left, out var nullKind, out _) && nullKind != 'z';
        }

        return false;
    }

    private static bool IsBooleanConstant(SqlBaseParser.BooleanExpressionContext? expr, bool expected)
    {
        if (expr is not SqlBaseParser.PredicatedContext predicated || predicated.predicate() != null)
            return false;

        var nested = TryGetParenthesizedBoolean(predicated.valueExpression());
        if (nested != null)
            return IsBooleanConstant(nested, expected);

        return TryGetConstant(predicated.valueExpression(), out var kind, out var text) && kind == 'b' &&
               text.Equals(expected ? "true" : "false", StringComparison.OrdinalIgnoreCase);
    }

    private static SqlBaseParser.BooleanExpressionContext? TryGetParenthesizedBoolean(SqlBaseParser.ValueExpressionContext? value)
    {
        if (value is SqlBaseParser.ValueExpressionDefaultContext valueDefault &&
            valueDefault.primaryExpression() is SqlBaseParser.ParenthesizedExpressionContext parenthesized)
        {
            return parenthesized.expression()?.booleanExpression();
        }
        return null;
    }

    /// <summary>
    /// Returns a literal constant: kind 'n' (numeric), 's' (string), 'b' (boolean) or 'z' (NULL). Parentheses are unwrapped.
    /// </summary>
    private static bool TryGetConstant(SqlBaseParser.ValueExpressionContext? value, out char kind, out string text)
    {
        kind = '\0';
        text = string.Empty;

        if (value is not SqlBaseParser.ValueExpressionDefaultContext valueDefault)
            return false;

        var primary = valueDefault.primaryExpression();
        if (primary is SqlBaseParser.ParenthesizedExpressionContext parenthesized)
        {
            if (parenthesized.expression()?.booleanExpression() is SqlBaseParser.PredicatedContext inner && inner.predicate() == null)
                return TryGetConstant(inner.valueExpression(), out kind, out text);
            return false;
        }

        if (primary is not SqlBaseParser.LiteralsContext literals)
            return false;

        switch (literals.literal())
        {
            case SqlBaseParser.NumericLiteralContext numeric:
                kind = 'n';
                text = numeric.GetText();
                return true;
            case SqlBaseParser.StringLiteralContext str:
                kind = 's';
                text = str.GetText();
                return true;
            case SqlBaseParser.BooleanLiteralContext boolean:
                kind = 'b';
                text = boolean.GetText();
                return true;
            case SqlBaseParser.NullLiteralContext:
                kind = 'z';
                text = "NULL";
                return true;
            default:
                return false;
        }
    }

    private static bool ConstantsEqual(char leftKind, string leftText, char rightKind, string rightText)
    {
        if (leftKind != rightKind || leftKind == 'z')
            return false;

        if (leftKind == 'n' &&
            decimal.TryParse(leftText, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var leftNumber) &&
            decimal.TryParse(rightText, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var rightNumber))
        {
            return leftNumber == rightNumber;
        }

        return leftKind == 'b'
            ? leftText.Equals(rightText, StringComparison.OrdinalIgnoreCase)
            : leftText.Equals(rightText, StringComparison.Ordinal);
    }

    private static bool IsSameColumnReference(SqlBaseParser.ValueExpressionContext left, SqlBaseParser.ValueExpressionContext right)
    {
        if (left is not SqlBaseParser.ValueExpressionDefaultContext leftDefault ||
            right is not SqlBaseParser.ValueExpressionDefaultContext rightDefault)
            return false;

        var leftPrimary = leftDefault.primaryExpression();
        var rightPrimary = rightDefault.primaryExpression();
        bool leftIsColumn = leftPrimary is SqlBaseParser.ColumnReferenceContext or SqlBaseParser.DereferenceContext;
        bool rightIsColumn = rightPrimary is SqlBaseParser.ColumnReferenceContext or SqlBaseParser.DereferenceContext;

        return leftIsColumn && rightIsColumn &&
               leftPrimary.GetText().Equals(rightPrimary.GetText(), StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// SEC H-15: Rejects DML that references masked (or denied, i.e. masked as NULL) columns of the target table.
    /// </summary>
    private void EnsureNoMaskedColumnReferences(string normalizedTableName, ParserRuleContext scope, string clause)
    {
        if (!_options.RejectMaskedColumnsInDml || _options.ColumnMaskingProvider == null)
            return;

        var stack = new Stack<IParseTree>();
        stack.Push(scope);
        while (stack.Count > 0)
        {
            var node = stack.Pop();
            string? candidate = node switch
            {
                SqlBaseParser.UpdateAssignmentContext assignment => assignment.identifier()?.GetText(),
                SqlBaseParser.ColumnReferenceContext columnRef => columnRef.identifier()?.GetText(),
                SqlBaseParser.DereferenceContext dereference => dereference.fieldName?.GetText(),
                _ => null
            };

            if (candidate != null)
            {
                string column = SqlIdentifierHelper.NormalizeIdentifier(candidate);
                if (column.Length > 0 && _options.ColumnMaskingProvider.HasMask(normalizedTableName, column))
                {
                    throw new SecurityException($"Masked column '{column}' of table '{normalizedTableName}' must not be referenced in {clause}.");
                }
            }

            for (int i = 0; i < node.ChildCount; i++)
            {
                stack.Push(node.GetChild(i));
            }
        }
    }

    /// <summary>
    /// SEC C-02: Only single-part names can refer to a CTE. Qualified names (schema.table) are always physical tables.
    /// </summary>
    private bool IsCte(SqlBaseParser.QualifiedNameContext qualifiedName)
    {
        var ids = qualifiedName.identifier();
        if (ids == null || ids.Length != 1)
            return false;

        return _cteScopeStack.Peek().Contains(SqlIdentifierHelper.FoldIdentifierForScope(ids[0].GetText()));
    }

    private bool HasMaskingForTable(string normalizedTableName)
    {
        if (_options.ColumnMaskingProvider == null || _options.TableColumnsProvider == null)
            return false;

        var columns = _options.TableColumnsProvider(normalizedTableName);
        if (columns == null || columns.Count == 0)
            return false;

        foreach (var col in columns)
        {
            if (_options.ColumnMaskingProvider.HasMask(normalizedTableName, col))
                return true;
        }

        return false;
    }

    private string BuildReplacement(ParserRuleContext context, string rawTableName, string normalizedTableName, bool shouldApplyRls)
    {
        string policyFilter = shouldApplyRls ? _options.PolicyProvider.GetPolicyFilter(normalizedTableName) : string.Empty;

        string selectColumns = "*";
        if (_options.TableColumnsProvider != null)
        {
            var columns = _options.TableColumnsProvider(normalizedTableName);
            if (columns != null && columns.Count > 0)
            {
                var projected = new List<string>(columns.Count);
                foreach (var col in columns)
                {
                    // SEC M-24: catalog column names are always emitted as delimited identifiers.
                    string quotedCol = SqlIdentifierHelper.QuoteIdentifier(col);
                    if (_options.ColumnMaskingProvider != null && _options.ColumnMaskingProvider.HasMask(normalizedTableName, col))
                    {
                        string maskExpr = _options.ColumnMaskingProvider.GetMaskedExpression(normalizedTableName, col);
                        projected.Add($"{maskExpr} AS {quotedCol}");
                    }
                    else
                    {
                        projected.Add(quotedCol);
                    }
                }
                selectColumns = string.Join(", ", projected);
            }
        }

        string subquery;
        if (!string.IsNullOrWhiteSpace(policyFilter))
        {
            subquery = $"(SELECT {selectColumns} FROM {rawTableName} WHERE {policyFilter})";
        }
        else
        {
            subquery = $"(SELECT {selectColumns} FROM {rawTableName})";
        }

        if (_options.AppendTableAlias)
        {
            // SEC-02: Check if relation already has an explicit alias
            bool hasExplicitAlias = false;
            if (context.Parent is SqlBaseParser.AliasedRelationContext aliasedRelation)
            {
                hasExplicitAlias = aliasedRelation.identifier() != null;
            }

            if (!hasExplicitAlias)
            {
                return $"{subquery} AS {rawTableName}";
            }
        }

        return subquery;
    }

    public string GetSecuredSql() => _rewriter.GetText();
}
