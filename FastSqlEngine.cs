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
    /// SEC C-06 / SQ-08: Maximum token-level nesting depth.
    /// </summary>
    public int MaxNestingDepth { get; set; } = 200;

    /// <summary>
    /// SEC C-06: Maximum depth of the resulting parse tree (checked iteratively after parsing, before any recursive
    /// tree walk). Guards against left-recursive chains (e.g. "1+1+1+...") that do not increase token nesting. 0 disables the check.
    /// </summary>
    public int MaxParseTreeDepth { get; set; } = 3_000;

    /// <summary>SQ-02: When true, comments are rejected to prevent dialect comment discrepancies.</summary>
    public bool RejectComments { get; set; } = false;

    /// <summary>SQ-01: When true, backslash escapes in string literals are rejected.</summary>
    public bool RejectBackslashInStrings { get; set; } = false;

    /// <summary>SQ-01: When true, string type constructors like E'...' are rejected.</summary>
    public bool RejectEscapedStringLiterals { get; set; } = false;

    /// <summary>SQ-02: When true, dollar-quoted strings ($$...$$) are rejected.</summary>
    public bool RejectDollarQuoting { get; set; } = false;

    /// <summary>SQ-10: When true, unquoted identifiers with non-ASCII characters are rejected.</summary>
    public bool RejectNonAsciiIdentifiers { get; set; } = false;

    /// <summary>SQ-11: When true, dots inside quoted identifiers are rejected.</summary>
    public bool RejectDotsInQuotedIdentifiers { get; set; } = false;

    /// <summary>SQ-13: When true, time-travel syntax (FOR TIMESTAMP/VERSION AS OF) is rejected.</summary>
    public bool RejectTimeTravelQueries { get; set; } = false;

    public (SqlBaseParser.SingleStatementContext Tree, CommonTokenStream Tokens) Parse(ReadOnlyMemory<char> sql)
    {
        if (sql.Length > MaxQueryLength)
        {
            throw new ArgumentOutOfRangeException(nameof(sql), $"SQL query length ({sql.Length}) exceeds the maximum allowed limit of {MaxQueryLength} characters.");
        }

        System.Runtime.CompilerServices.RuntimeHelpers.EnsureSufficientExecutionStack();

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

        IToken? lastNonWsToken = null;

        foreach (var token in all)
        {
            int type = token.Type;
            string? text = token.Text;

            // SQ-02: Block comment nesting check (/* ... /* ... */)
            if (type == SqlBaseLexer.BRACKETED_COMMENT)
            {
                if (text != null && text.Length > 4 && text.IndexOf("/*", 2, StringComparison.Ordinal) >= 0)
                {
                    throw new ParseCanceledException(
                        $"line {token.Line}:{token.Column}: Nested block comments ('/* ... /* ... */') are strictly prohibited due to dialect lexer differentials.");
                }
            }

            if (RejectComments && (type == SqlBaseLexer.SIMPLE_COMMENT || type == SqlBaseLexer.BRACKETED_COMMENT))
            {
                throw new ParseCanceledException(
                    $"line {token.Line}:{token.Column}: SQL comments are not permitted in governed execution.");
            }

            if (type == SqlBaseLexer.WS || type == SqlBaseLexer.SIMPLE_COMMENT || type == SqlBaseLexer.BRACKETED_COMMENT)
                continue;

            // SQ-01: Backslash escapes in string literals
            if (RejectBackslashInStrings && type == SqlBaseLexer.STRING && text != null && text.Contains('\\'))
            {
                throw new ParseCanceledException(
                    $"line {token.Line}:{token.Column}: Backslash escapes in string literals are not permitted due to dialect lexer differentials.");
            }

            // SQ-01: E'...' / e'...' string type constructor
            if (RejectEscapedStringLiterals && (type == SqlBaseLexer.STRING || type == SqlBaseLexer.UNICODE_STRING))
            {
                if (lastNonWsToken != null && lastNonWsToken.Type == SqlBaseLexer.IDENTIFIER &&
                    string.Equals(lastNonWsToken.Text, "E", StringComparison.OrdinalIgnoreCase))
                {
                    throw new ParseCanceledException(
                        $"line {token.Line}:{token.Column}: Escaped string literal type constructors (E'...') are not permitted due to dialect lexer differentials.");
                }
            }

            // SQ-02: Dollar quoting ($$...$$)
            if (RejectDollarQuoting && type == SqlBaseLexer.DOLLAR_STRING)
            {
                throw new ParseCanceledException(
                    $"line {token.Line}:{token.Column}: Dollar-quoted strings ($$...$$) are not permitted.");
            }

            // SQ-10: Non-ASCII in unquoted identifier
            if (RejectNonAsciiIdentifiers && type == SqlBaseLexer.IDENTIFIER && text != null)
            {
                for (int ci = 0; ci < text.Length; ci++)
                {
                    if (text[ci] > 127)
                    {
                        throw new ParseCanceledException(
                            $"line {token.Line}:{token.Column}: Non-ASCII characters in unquoted identifier '{text}' are not permitted.");
                    }
                }
            }

            // SQ-11: Dots in quoted identifiers ("a.b")
            if (RejectDotsInQuotedIdentifiers && (type == SqlBaseLexer.QUOTED_IDENTIFIER || type == SqlBaseLexer.BACKQUOTED_IDENTIFIER) && text != null && text.Contains('.'))
            {
                throw new ParseCanceledException(
                    $"line {token.Line}:{token.Column}: Dots inside quoted identifiers ({text}) are not permitted.");
            }

            // SQ-13: Time-travel queries (FOR TIMESTAMP/VERSION AS OF)
            if (RejectTimeTravelQueries && (type == SqlBaseLexer.TIMESTAMP || type == SqlBaseLexer.VERSION))
            {
                if (lastNonWsToken != null && lastNonWsToken.Type == SqlBaseLexer.FOR)
                {
                    throw new ParseCanceledException(
                        $"line {token.Line}:{token.Column}: Time-travel queries (FOR TIMESTAMP/VERSION AS OF) are not permitted.");
                }
            }

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
            lastNonWsToken = token;

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
        bool oldComments = RejectComments;
        bool oldBackslash = RejectBackslashInStrings;
        bool oldEscaped = RejectEscapedStringLiterals;
        bool oldDollar = RejectDollarQuoting;
        bool oldNonAscii = RejectNonAsciiIdentifiers;
        bool oldDots = RejectDotsInQuotedIdentifiers;
        bool oldTimeTravel = RejectTimeTravelQueries;

        if (options != null)
        {
            RejectComments = options.RejectComments;
            RejectBackslashInStrings = options.RejectBackslashInStrings;
            RejectEscapedStringLiterals = options.RejectEscapedStringLiterals;
            RejectDollarQuoting = options.RejectDollarQuoting || (options.TargetDialect == TargetSqlDialect.SqlServer);
            RejectNonAsciiIdentifiers = options.RejectNonAsciiIdentifiers;
            RejectDotsInQuotedIdentifiers = options.RejectDotsInQuotedIdentifiers;
            RejectTimeTravelQueries = options.RejectTimeTravelQueries;
        }

        try
        {
            var (tree, tokens) = Parse(sql);
            var listener = new RlsListener(tokens, options);
            ParseTreeWalker.Default.Walk(listener, tree);
            return listener.GetSecuredSql();
        }
        finally
        {
            RejectComments = oldComments;
            RejectBackslashInStrings = oldBackslash;
            RejectEscapedStringLiterals = oldEscaped;
            RejectDollarQuoting = oldDollar;
            RejectNonAsciiIdentifiers = oldNonAscii;
            RejectDotsInQuotedIdentifiers = oldDots;
            RejectTimeTravelQueries = oldTimeTravel;
        }
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
