namespace TrinoSqlEngine.Analysis;

using System;
using System.Collections.Generic;
using Antlr4.Runtime.Tree;

public sealed class SqlQueryAnalyzer : SqlBaseBaseListener, ISqlQueryAnalyzer
{
    private SqlStatementType _statementType = SqlStatementType.Other;
    private readonly List<TableAccessTarget> _referencedTables = new();
    private readonly List<string> _projectedColumns = new();
    private readonly HashSet<string> _seenTableKeys = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _joinConditionColumns = new(StringComparer.OrdinalIgnoreCase);
    private readonly Stack<HashSet<string>> _cteScopeStack = new();

    private int _joinCount;
    private int _currentSubqueryDepth;
    private int _maxSubqueryDepth;
    private bool _hasExplicitLimit;
    private long? _explicitLimitValue;
    private bool _isRootQuerySpecification = true;

    public SqlQueryAnalyzer()
    {
        _cteScopeStack.Push(new HashSet<string>(StringComparer.OrdinalIgnoreCase));
    }

    public SqlQueryMetadata Analyze(SqlBaseParser.SingleStatementContext statementContext)
    {
        ArgumentNullException.ThrowIfNull(statementContext);

        Reset();
        ParseTreeWalker.Default.Walk(this, statementContext);

        return new SqlQueryMetadata(
            StatementType: _statementType,
            ReferencedTables: _referencedTables.AsReadOnly(),
            ProjectedColumns: _projectedColumns.AsReadOnly(),
            JoinCount: _joinCount,
            MaxSubqueryDepth: _maxSubqueryDepth,
            HasExplicitLimit: _hasExplicitLimit,
            ExplicitLimitValue: _explicitLimitValue,
            JoinConditionColumns: new HashSet<string>(_joinConditionColumns, StringComparer.OrdinalIgnoreCase));
    }

    private void Reset()
    {
        _statementType = SqlStatementType.Other;
        _referencedTables.Clear();
        _projectedColumns.Clear();
        _seenTableKeys.Clear();
        _joinConditionColumns.Clear();
        _cteScopeStack.Clear();
        _cteScopeStack.Push(new HashSet<string>(StringComparer.OrdinalIgnoreCase));
        _joinCount = 0;
        _currentSubqueryDepth = 0;
        _maxSubqueryDepth = 0;
        _hasExplicitLimit = false;
        _explicitLimitValue = null;
        _isRootQuerySpecification = true;
    }

    public override void EnterSingleStatement(SqlBaseParser.SingleStatementContext context)
    {
        var stmt = context.statement();
        if (stmt == null) return;

        _statementType = stmt switch
        {
            SqlBaseParser.StatementDefaultContext => SqlStatementType.Select,
            SqlBaseParser.InsertIntoContext => SqlStatementType.Insert,
            SqlBaseParser.UpdateContext => SqlStatementType.Update,
            SqlBaseParser.DeleteContext => SqlStatementType.Delete,
            SqlBaseParser.CreateTableContext or
            SqlBaseParser.CreateTableAsSelectContext or
            SqlBaseParser.DropTableContext or
            SqlBaseParser.TruncateTableContext or
            SqlBaseParser.RenameTableContext or
            SqlBaseParser.AddColumnContext or
            SqlBaseParser.RenameColumnContext or
            SqlBaseParser.DropColumnContext or
            SqlBaseParser.SetDefaultValueContext or
            SqlBaseParser.DropDefaultValueContext or
            SqlBaseParser.SetColumnTypeContext or
            SqlBaseParser.DropNotNullConstraintContext or
            SqlBaseParser.SetTablePropertiesContext or
            SqlBaseParser.TableExecuteContext or
            SqlBaseParser.CreateViewContext or
            SqlBaseParser.DropViewContext or
            SqlBaseParser.CreateMaterializedViewContext or
            SqlBaseParser.DropMaterializedViewContext or
            SqlBaseParser.CreateSchemaContext or
            SqlBaseParser.DropSchemaContext or
            SqlBaseParser.RenameSchemaContext or
            SqlBaseParser.GrantRolesContext or
            SqlBaseParser.GrantPrivilegesContext or
            SqlBaseParser.RevokeRolesContext or
            SqlBaseParser.RevokePrivilegesContext or
            SqlBaseParser.DenyContext => SqlStatementType.Ddl,
            _ => SqlStatementType.Other
        };
    }

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

    public override void ExitNamedQuery(SqlBaseParser.NamedQueryContext context)
    {
        string cteName = SqlIdentifierHelper.NormalizeIdentifier(context.name.GetText());
        _cteScopeStack.Peek().Add(cteName);
    }

    public override void EnterSubquery(SqlBaseParser.SubqueryContext context)
    {
        _currentSubqueryDepth++;
        if (_currentSubqueryDepth > _maxSubqueryDepth)
        {
            _maxSubqueryDepth = _currentSubqueryDepth;
        }
    }

    public override void ExitSubquery(SqlBaseParser.SubqueryContext context)
    {
        if (_currentSubqueryDepth > 0)
        {
            _currentSubqueryDepth--;
        }
    }

    public override void EnterSubqueryRelation(SqlBaseParser.SubqueryRelationContext context)
    {
        _currentSubqueryDepth++;
        if (_currentSubqueryDepth > _maxSubqueryDepth)
        {
            _maxSubqueryDepth = _currentSubqueryDepth;
        }
    }

    public override void ExitSubqueryRelation(SqlBaseParser.SubqueryRelationContext context)
    {
        if (_currentSubqueryDepth > 0)
        {
            _currentSubqueryDepth--;
        }
    }

    public override void EnterQuerySpecification(SqlBaseParser.QuerySpecificationContext context)
    {
        if (context.relation() != null && context.relation().Length > 1)
        {
            _joinCount += (context.relation().Length - 1);
        }

        if (_isRootQuerySpecification && _currentSubqueryDepth == 0)
        {
            _isRootQuerySpecification = false;
            var selectItems = context.selectItem();
            if (selectItems != null)
            {
                foreach (var item in selectItems)
                {
                    if (item is SqlBaseParser.SelectSingleContext single)
                    {
                        if (single.identifier() != null)
                        {
                            _projectedColumns.Add(SqlIdentifierHelper.NormalizeIdentifier(single.identifier().GetText()));
                        }
                        else if (single.expression() != null)
                        {
                            _projectedColumns.Add(single.expression().GetText());
                        }
                    }
                    else if (item is SqlBaseParser.SelectAllContext all)
                    {
                        _projectedColumns.Add(all.GetText());
                    }
                }
            }
        }
    }

    public override void EnterJoinRelation(SqlBaseParser.JoinRelationContext context)
    {
        _joinCount++;
    }

    public override void EnterJoinCriteria(SqlBaseParser.JoinCriteriaContext context)
    {
        ExtractIdentifiers(context, _joinConditionColumns);
    }

    public override void EnterComparison(SqlBaseParser.ComparisonContext context)
    {
        var op = context.comparisonOperator();
        if (op != null && (op.EQ() != null || string.Equals(op.GetText(), "=", StringComparison.Ordinal)))
        {
            var leftCtx = context.value ?? (context.Parent as SqlBaseParser.PredicatedContext)?.valueExpression();
            var rightCtx = context.right ?? context.valueExpression();

            if (leftCtx != null && rightCtx != null)
            {
                var leftIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var rightIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                ExtractIdentifiers(leftCtx, leftIds);
                ExtractIdentifiers(rightCtx, rightIds);

                // If identifiers exist on BOTH sides of equality (e.g. a.col = b.col),
                // this is a relational equijoin predicate (e.g. ANSI-89 comma join in WHERE clause)
                if (leftIds.Count > 0 && rightIds.Count > 0)
                {
                    foreach (var id in leftIds) _joinConditionColumns.Add(id);
                    foreach (var id in rightIds) _joinConditionColumns.Add(id);
                }
            }
        }
    }

    private static void ExtractIdentifiers(Antlr4.Runtime.RuleContext? ctx, HashSet<string> identifiers)
    {
        if (ctx == null) return;
        if (ctx is SqlBaseParser.IdentifierContext id)
        {
            string name = SqlIdentifierHelper.NormalizeIdentifier(id.GetText());
            if (!string.IsNullOrWhiteSpace(name))
            {
                identifiers.Add(name);
            }
        }
        for (int i = 0; i < ctx.ChildCount; i++)
        {
            if (ctx.GetChild(i) is Antlr4.Runtime.RuleContext child)
            {
                ExtractIdentifiers(child, identifiers);
            }
        }
    }

    public override void EnterQueryNoWith(SqlBaseParser.QueryNoWithContext context)
    {
        // Check top-level limit if encountered at root depth
        if (_currentSubqueryDepth == 0 && context.limit != null)
        {
            _hasExplicitLimit = true;
            if (context.limit.rowCount() != null)
            {
                string text = context.limit.rowCount().GetText();
                if (long.TryParse(text, out long limitVal))
                {
                    _explicitLimitValue = limitVal;
                }
            }
        }
    }

    public override void EnterTableName(SqlBaseParser.TableNameContext context)
    {
        RecordTableAccess(context.qualifiedName(), context.Parent as SqlBaseParser.AliasedRelationContext);
    }

    public override void EnterTable(SqlBaseParser.TableContext context)
    {
        RecordTableAccess(context.qualifiedName(), null);
    }

    public override void EnterTableArgumentTable(SqlBaseParser.TableArgumentTableContext context)
    {
        RecordTableAccess(context.qualifiedName(), null);
    }

    public override void EnterDelete(SqlBaseParser.DeleteContext context)
    {
        RecordTableAccess(context.qualifiedName(), null);
    }

    public override void EnterUpdate(SqlBaseParser.UpdateContext context)
    {
        RecordTableAccess(context.qualifiedName(), null);
    }

    public override void EnterInsertInto(SqlBaseParser.InsertIntoContext context)
    {
        RecordTableAccess(context.qualifiedName(), null);
    }

    private void RecordTableAccess(SqlBaseParser.QualifiedNameContext qualifiedNameContext, SqlBaseParser.AliasedRelationContext? aliasedRelation)
    {
        if (qualifiedNameContext == null) return;

        string normalizedFullName = SqlIdentifierHelper.NormalizeQualifiedName(qualifiedNameContext);
        if (string.IsNullOrWhiteSpace(normalizedFullName)) return;

        // Skip if this is a CTE in current scope
        if (_cteScopeStack.Peek().Contains(normalizedFullName))
        {
            return;
        }

        string? alias = null;
        if (aliasedRelation?.identifier() != null)
        {
            alias = SqlIdentifierHelper.NormalizeIdentifier(aliasedRelation.identifier().GetText());
        }

        var ids = qualifiedNameContext.identifier();
        string? catalog = null;
        string? schema = null;
        string tableName;

        if (ids != null && ids.Length >= 3)
        {
            catalog = SqlIdentifierHelper.NormalizeIdentifier(ids[0].GetText());
            schema = SqlIdentifierHelper.NormalizeIdentifier(ids[1].GetText());
            tableName = SqlIdentifierHelper.NormalizeIdentifier(ids[2].GetText());
        }
        else if (ids != null && ids.Length == 2)
        {
            schema = SqlIdentifierHelper.NormalizeIdentifier(ids[0].GetText());
            tableName = SqlIdentifierHelper.NormalizeIdentifier(ids[1].GetText());
        }
        else if (ids != null && ids.Length == 1)
        {
            tableName = SqlIdentifierHelper.NormalizeIdentifier(ids[0].GetText());
        }
        else
        {
            tableName = normalizedFullName;
        }

        string dedupeKey = $"{catalog ?? ""}.{schema ?? ""}.{tableName}->{alias ?? ""}";
        if (_seenTableKeys.Add(dedupeKey))
        {
            _referencedTables.Add(new TableAccessTarget(
                Catalog: catalog,
                Schema: schema,
                TableName: tableName,
                Alias: alias,
                FullName: normalizedFullName));
        }
    }
}
