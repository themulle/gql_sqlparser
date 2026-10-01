namespace TrinoSqlEngine;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using Antlr4.Runtime;

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

    public RlsListener(ITokenStream tokens, RlsOptions? options = null)
    {
        _rewriter = new TokenStreamRewriter(tokens);
        _options = options ?? new RlsOptions();
        _cteScopeStack.Push(new HashSet<string>(StringComparer.OrdinalIgnoreCase));
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

    // SEC-05: Lexical CTE Scoping
    public override void EnterQuery(SqlBaseParser.QueryContext context)
    {
        _cteScopeStack.Push(new HashSet<string>(_cteScopeStack.Peek(), StringComparer.OrdinalIgnoreCase));
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
    public override void ExitNamedQuery(SqlBaseParser.NamedQueryContext context)
    {
        string cteName = SqlIdentifierHelper.NormalizeIdentifier(context.name.GetText());
        _cteScopeStack.Peek().Add(cteName);
    }

    private int _subqueryDepth = 0;
    private bool _rootLimitHandled = false;

    public override void EnterSubquery(SqlBaseParser.SubqueryContext context)
    {
        _subqueryDepth++;
    }

    public override void ExitSubquery(SqlBaseParser.SubqueryContext context)
    {
        if (_subqueryDepth > 0) _subqueryDepth--;
    }

    public override void EnterSubqueryRelation(SqlBaseParser.SubqueryRelationContext context)
    {
        _subqueryDepth++;
    }

    public override void ExitSubqueryRelation(SqlBaseParser.SubqueryRelationContext context)
    {
        if (_subqueryDepth > 0) _subqueryDepth--;
    }

    public override void EnterQueryNoWith(SqlBaseParser.QueryNoWithContext context)
    {
        if (_options.EnforcedMaxRows > 0 && _subqueryDepth == 0 && !_rootLimitHandled)
        {
            if (context.limit != null)
            {
                _rootLimitHandled = true;
                if (context.limit.rowCount() != null)
                {
                    string text = context.limit.rowCount().GetText();
                    if (long.TryParse(text, out long existingVal))
                    {
                        if (existingVal > _options.EnforcedMaxRows)
                        {
                            _rewriter.Replace(context.limit.rowCount().Start, context.limit.rowCount().Stop, _options.EnforcedMaxRows.ToString());
                        }
                    }
                    else
                    {
                        _rewriter.Replace(context.limit.rowCount().Start, context.limit.rowCount().Stop, _options.EnforcedMaxRows.ToString());
                    }
                }
                else if (context.limit.ALL() != null)
                {
                    _rewriter.Replace(context.limit.ALL().Symbol, _options.EnforcedMaxRows.ToString());
                }
            }
        }
    }

    public override void ExitQueryNoWith(SqlBaseParser.QueryNoWithContext context)
    {
        if (_options.EnforcedMaxRows > 0 && _subqueryDepth == 0 && !_rootLimitHandled)
        {
            _rootLimitHandled = true;
            _rewriter.InsertAfter(context.Stop, $" LIMIT {_options.EnforcedMaxRows}");
        }
    }

    // Standard SELECT relation: FROM orders (relationPrimary: qualifiedName -> #tableName)
    public override void EnterTableName(SqlBaseParser.TableNameContext context)
    {
        string rawName = context.qualifiedName().GetText();
        string normalizedName = SqlIdentifierHelper.NormalizeQualifiedName(context.qualifiedName());

        if (IsCte(normalizedName))
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

        if (IsCte(normalizedName))
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

        if (IsCte(normalizedName))
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
        string rawName = context.qualifiedName().GetText();
        string normalizedName = SqlIdentifierHelper.NormalizeQualifiedName(context.qualifiedName());

        if (IsCte(normalizedName) || !_options.PolicyProvider.ShouldApplyPolicy(normalizedName))
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
        string rawName = context.qualifiedName().GetText();
        string normalizedName = SqlIdentifierHelper.NormalizeQualifiedName(context.qualifiedName());

        // 1. WITH CHECK OPTION verification on assignments
        if (_options.EnforceWithCheckOption && context.updateAssignment() != null)
        {
            string expectedTenant = _options.ExpectedTenantValue.Trim('\'', '"');

            foreach (var assignment in context.updateAssignment())
            {
                string colName = SqlIdentifierHelper.NormalizeIdentifier(assignment.identifier().GetText());
                if (colName.Equals(_options.TenantColumnName, StringComparison.OrdinalIgnoreCase))
                {
                    if (_options.DisallowTenantColumnModificationInUpdate)
                    {
                        throw new SecurityException($"Modification of tenant column '{colName}' is not allowed in UPDATE statement.");
                    }

                    string assignedVal = assignment.expression().GetText().Trim('\'', '"');
                    if (!assignedVal.Equals(expectedTenant, StringComparison.OrdinalIgnoreCase))
                    {
                        throw new SecurityException($"Tenant column '{colName}' assignment value '{assignedVal}' does not match expected tenant '{expectedTenant}'.");
                    }
                }
            }
        }

        // 2. WHERE clause injection
        if (IsCte(normalizedName) || !_options.PolicyProvider.ShouldApplyPolicy(normalizedName))
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

        var rootQuery = context.rootQuery();
        if (rootQuery == null)
            return;

        string expectedTenant = _options.ExpectedTenantValue.Trim('\'', '"');

        // A: Check inline VALUES clause
        var inlineTable = FindInlineTable(rootQuery);
        if (inlineTable != null)
        {
            var rowExpressions = inlineTable.expression();
            if (rowExpressions != null)
            {
                foreach (var rowExpr in rowExpressions)
                {
                    var values = ExtractRowExpressions(rowExpr);
                    if (values != null && tenantIndex < values.Count)
                    {
                        string valText = values[tenantIndex].GetText().Trim('\'', '"');
                        if (!valText.Equals(expectedTenant, StringComparison.OrdinalIgnoreCase))
                        {
                            throw new SecurityException($"Tenant column '{_options.TenantColumnName}' inserted value '{valText}' does not match expected tenant '{expectedTenant}'.");
                        }
                    }
                }
            }
        }

        // B: Check INSERT INTO ... SELECT constant/literal projections
        var querySpec = FindQuerySpecification(rootQuery);
        if (querySpec != null)
        {
            var items = querySpec.selectItem();
            if (items != null && tenantIndex < items.Length)
            {
                if (items[tenantIndex] is SqlBaseParser.SelectSingleContext singleItem && singleItem.expression() != null)
                {
                    var expr = singleItem.expression();
                    // If expression is a primary literal (number, string)
                    string text = expr.GetText().Trim('\'', '"');
                    if (IsLiteralConstant(expr) && !text.Equals(expectedTenant, StringComparison.OrdinalIgnoreCase))
                    {
                        throw new SecurityException($"Tenant column '{_options.TenantColumnName}' in INSERT SELECT value '{text}' does not match expected tenant '{expectedTenant}'.");
                    }
                }
            }
        }
    }

    private static bool IsLiteralConstant(SqlBaseParser.ExpressionContext expr)
    {
        // Simple check: if expression text is purely numeric or quoted string
        string t = expr.GetText();
        if (string.IsNullOrWhiteSpace(t)) return false;
        if (long.TryParse(t, out _) || double.TryParse(t, out _)) return true;
        if ((t.StartsWith('\'') && t.EndsWith('\'')) || (t.StartsWith('"') && t.EndsWith('"'))) return true;
        return false;
    }

    private static SqlBaseParser.InlineTableContext? FindInlineTable(RuleContext? ctx)
    {
        if (ctx == null) return null;
        if (ctx is SqlBaseParser.InlineTableContext inlineTable) return inlineTable;
        for (int i = 0; i < ctx.ChildCount; i++)
        {
            if (ctx.GetChild(i) is RuleContext child)
            {
                var found = FindInlineTable(child);
                if (found != null) return found;
            }
        }
        return null;
    }

    private static SqlBaseParser.QuerySpecificationContext? FindQuerySpecification(RuleContext? ctx)
    {
        if (ctx == null) return null;
        if (ctx is SqlBaseParser.QuerySpecificationContext spec) return spec;
        for (int i = 0; i < ctx.ChildCount; i++)
        {
            if (ctx.GetChild(i) is RuleContext child)
            {
                var found = FindQuerySpecification(child);
                if (found != null) return found;
            }
        }
        return null;
    }

    private static IReadOnlyList<SqlBaseParser.ExpressionContext>? ExtractRowExpressions(SqlBaseParser.ExpressionContext expr)
    {
        var row = FindRowConstructor(expr);
        if (row != null)
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

        return new[] { expr };
    }

    private static SqlBaseParser.RowConstructorContext? FindRowConstructor(RuleContext? ctx)
    {
        if (ctx == null) return null;
        if (ctx is SqlBaseParser.RowConstructorContext row) return row;
        for (int i = 0; i < ctx.ChildCount; i++)
        {
            if (ctx.GetChild(i) is RuleContext child)
            {
                var found = FindRowConstructor(child);
                if (found != null) return found;
            }
        }
        return null;
    }

    private bool IsCte(string normalizedTableName)
    {
        return _cteScopeStack.Peek().Contains(normalizedTableName);
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
                    if (_options.ColumnMaskingProvider != null && _options.ColumnMaskingProvider.HasMask(normalizedTableName, col))
                    {
                        string maskExpr = _options.ColumnMaskingProvider.GetMaskedExpression(normalizedTableName, col);
                        projected.Add($"{maskExpr} AS {col}");
                    }
                    else
                    {
                        projected.Add(col);
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
