namespace TrinoSqlEngine;

using System;
using System.Collections.Generic;
using System.IO;
using Antlr4.Runtime;
using Antlr4.Runtime.Atn;
using Antlr4.Runtime.Misc;
using Antlr4.Runtime.Tree;
using Microsoft.Extensions.ObjectPool;

public sealed class ThrowingErrorListener : BaseErrorListener, IAntlrErrorListener<int>
{
    public static readonly ThrowingErrorListener Instance = new();

    public override void SyntaxError(TextWriter output, IRecognizer recognizer, IToken offendingSymbol, int line, int charPositionInLine, string msg, RecognitionException e)
    {
        throw new ParseCanceledException($"line {line}:{charPositionInLine}: {msg}", e);
    }

    public void SyntaxError(TextWriter output, IRecognizer recognizer, int offendingSymbol, int line, int charPositionInLine, string msg, RecognitionException e)
    {
        throw new ParseCanceledException($"line {line}:{charPositionInLine}: {msg}", e);
    }
}

public sealed class FastSqlEngine
{
    private readonly ObjectPool<SqlBaseParser> _parserPool = 
        new DefaultObjectPool<SqlBaseParser>(new ParserPooledObjectPolicy());

    /// <summary>
    /// SEC-04: Maximum allowed SQL query length in characters to prevent algorithmic DoS and StackOverflow attacks.
    /// SEC C-06: Default lowered from 512k to 64k.
    /// </summary>
    public int MaxQueryLength { get; set; } = 65_536;

    /// <summary>
    /// SEC C-06: Maximum token-level nesting depth (parentheses, brackets, CASE/BEGIN ... END, legacy ARRAY/MAP type
    /// brackets, lambda arrows and chains of unary operators). Checked before parsing, because the recursive-descent
    /// parser and the tree walker would otherwise raise an uncatchable StackOverflowException. 0 disables the check.
    /// </summary>
    public int MaxNestingDepth { get; set; } = 200;

    /// <summary>
    /// SEC C-06: Maximum depth of the resulting parse tree (checked iteratively after parsing, before any recursive
    /// tree walk). Guards against left-recursive chains (e.g. "1+1+1+...") that do not increase token nesting. 0 disables the check.
    /// </summary>
    public int MaxParseTreeDepth { get; set; } = 3_000;

    public (SqlBaseParser.SingleStatementContext Tree, CommonTokenStream Tokens) Parse(ReadOnlyMemory<char> sql)
    {
        if (sql.Length > MaxQueryLength)
        {
            throw new ArgumentOutOfRangeException(nameof(sql), $"SQL query length ({sql.Length}) exceeds the maximum allowed limit of {MaxQueryLength} characters.");
        }

        var charStream = new ZeroCopyCaseInsensitiveStream(sql);
        var lexer = new SqlBaseLexer(charStream);
        lexer.RemoveErrorListeners();
        lexer.AddErrorListener(ThrowingErrorListener.Instance);

        var tokens = new CommonTokenStream(lexer);
        EnsureNestingDepthWithinLimit(tokens);
        
        var parser = _parserPool.Get();
        try
        {
            parser.TokenStream = tokens;

            SqlBaseParser.SingleStatementContext tree;

            // Stufe 1: Schneller SLL-Pfad (im Pool bereits vorkonfiguriert)
            try
            {
                tree = parser.singleStatement();
            }
            catch (ParseCanceledException)
            {
                // Stufe 2: Fallback auf LL(*)-Modus
                tokens.Reset();
                parser.Reset();
                parser.AddErrorListener(ThrowingErrorListener.Instance);
                // SEC N1: DefaultErrorStrategy holds per-parse state; never share an instance between threads.
                parser.ErrorHandler = new DefaultErrorStrategy();
                parser.Interpreter.PredictionMode = PredictionMode.LL;
                
                tree = parser.singleStatement();
                if (parser.NumberOfSyntaxErrors > 0)
                {
                    throw new ParseCanceledException($"Parsing failed with {parser.NumberOfSyntaxErrors} syntax errors.");
                }
            }

            // SEC C-06: reject overly deep trees before any recursive walk by the caller.
            EnsureParseTreeDepthWithinLimit(tree);
            return (tree, tokens);
        }
        finally
        {
            _parserPool.Return(parser);
        }
    }

    public (SqlBaseParser.StandaloneExpressionContext Tree, CommonTokenStream Tokens) ParseExpression(ReadOnlyMemory<char> sql)
    {
        if (sql.Length > MaxQueryLength)
        {
            throw new ArgumentOutOfRangeException(nameof(sql), $"SQL expression length ({sql.Length}) exceeds the maximum allowed limit of {MaxQueryLength} characters.");
        }

        var charStream = new ZeroCopyCaseInsensitiveStream(sql);
        var lexer = new SqlBaseLexer(charStream);
        lexer.RemoveErrorListeners();
        lexer.AddErrorListener(ThrowingErrorListener.Instance);

        var tokens = new CommonTokenStream(lexer);
        EnsureNestingDepthWithinLimit(tokens);
        
        var parser = _parserPool.Get();
        try
        {
            parser.TokenStream = tokens;

            SqlBaseParser.StandaloneExpressionContext tree;

            // Stufe 1: Schneller SLL-Pfad (im Pool bereits vorkonfiguriert)
            try
            {
                tree = parser.standaloneExpression();
            }
            catch (ParseCanceledException)
            {
                // Stufe 2: Fallback auf LL(*)-Modus
                tokens.Reset();
                parser.Reset();
                parser.AddErrorListener(ThrowingErrorListener.Instance);
                // SEC N1: DefaultErrorStrategy holds per-parse state; never share an instance between threads.
                parser.ErrorHandler = new DefaultErrorStrategy();
                parser.Interpreter.PredictionMode = PredictionMode.LL;
                
                tree = parser.standaloneExpression();
                if (parser.NumberOfSyntaxErrors > 0)
                {
                    throw new ParseCanceledException($"Parsing failed with {parser.NumberOfSyntaxErrors} syntax errors.");
                }
            }

            // SEC C-06: reject overly deep trees before any recursive walk by the caller.
            EnsureParseTreeDepthWithinLimit(tree);
            return (tree, tokens);
        }
        finally
        {
            _parserPool.Return(parser);
        }
    }

    /// <summary>
    /// SEC C-06: Token-level nesting check before parsing. Fills the token stream (lexer errors surface here as
    /// <see cref="ParseCanceledException"/>, exactly as they would during parsing).
    /// </summary>
    private void EnsureNestingDepthWithinLimit(CommonTokenStream tokens)
    {
        if (MaxNestingDepth <= 0) return;

        tokens.Fill();
        var all = tokens.GetTokens();

        int parenDepth = 0;   // ( ) and [ ]
        int blockDepth = 0;   // CASE/BEGIN ... END
        int typeDepth = 0;    // ARRAY< / MAP< ... >
        int lambdaCount = 0;  // '->' (lambda bodies nest without closing token)
        int unaryRun = 0;     // consecutive prefix operators (- + NOT)
        int previousType = 0;

        foreach (var token in all)
        {
            int type = token.Type;
            if (type == SqlBaseLexer.WS || type == SqlBaseLexer.SIMPLE_COMMENT || type == SqlBaseLexer.BRACKETED_COMMENT)
                continue;

            string? text = token.Text;
            bool isUnaryCandidate = false;

            if (type == SqlBaseLexer.CASE || type == SqlBaseLexer.BEGIN)
            {
                blockDepth++;
            }
            else if (type == SqlBaseLexer.END)
            {
                if (blockDepth > 0) blockDepth--;
            }
            else if (type == SqlBaseLexer.LT && (previousType == SqlBaseLexer.ARRAY || previousType == SqlBaseLexer.MAP))
            {
                typeDepth++;
            }
            else if (type == SqlBaseLexer.GT)
            {
                if (typeDepth > 0) typeDepth--;
            }
            else if (type == SqlBaseLexer.MINUS || type == SqlBaseLexer.PLUS || type == SqlBaseLexer.NOT)
            {
                isUnaryCandidate = true;
            }
            else if (text == "(" || text == "[")
            {
                parenDepth++;
            }
            else if (text == ")" || text == "]")
            {
                if (parenDepth > 0) parenDepth--;
            }
            else if (text == "->")
            {
                lambdaCount++;
            }

            unaryRun = isUnaryCandidate ? unaryRun + 1 : 0;
            previousType = type;

            int depth = parenDepth + blockDepth + typeDepth + lambdaCount + unaryRun;
            if (depth > MaxNestingDepth)
            {
                throw new ParseCanceledException(
                    $"line {token.Line}:{token.Column}: SQL nesting depth exceeds the maximum allowed limit of {MaxNestingDepth}.");
            }
        }
    }

    /// <summary>
    /// SEC C-06: Iterative (non-recursive) parse tree depth check, executed before any recursive tree walk.
    /// </summary>
    private void EnsureParseTreeDepthWithinLimit(IParseTree tree)
    {
        if (MaxParseTreeDepth <= 0) return;

        var stack = new Stack<(IParseTree Node, int Depth)>();
        stack.Push((tree, 1));
        while (stack.Count > 0)
        {
            var (node, depth) = stack.Pop();
            if (depth > MaxParseTreeDepth)
            {
                throw new ParseCanceledException(
                    $"SQL parse tree depth exceeds the maximum allowed limit of {MaxParseTreeDepth}.");
            }

            for (int i = 0; i < node.ChildCount; i++)
            {
                var child = node.GetChild(i);
                if (child.ChildCount > 0)
                {
                    stack.Push((child, depth + 1));
                }
            }
        }
    }

    /// <summary>
    /// Architecture A3: High-level Façade method for secure RLS rewriting.
    /// </summary>
    public string RewriteRls(ReadOnlyMemory<char> sql, RlsOptions? options = null)
    {
        var (tree, tokens) = Parse(sql);
        var listener = new RlsListener(tokens, options);
        ParseTreeWalker.Default.Walk(listener, tree);
        return listener.GetSecuredSql();
    }

    /// <summary>
    /// Analyzes a SQL query AST for statement type, referenced physical tables, projected columns, and query metrics.
    /// </summary>
    public Analysis.SqlQueryMetadata Analyze(ReadOnlyMemory<char> sql)
    {
        var (tree, _) = Parse(sql);
        var analyzer = new Analysis.SqlQueryAnalyzer();
        return analyzer.Analyze(tree);
    }
}
