namespace TrinoSqlEngine;

using Antlr4.Runtime.Atn;
using Microsoft.Extensions.ObjectPool;

public class ParserPooledObjectPolicy : IPooledObjectPolicy<SqlBaseParser>
{
    public SqlBaseParser Create()
    {
        var parser = new SqlBaseParser(null);
        // Gemeinsamen ATN-Simulator injizieren
        parser.SetInterpreter(new ParserATNSimulator(
            parser, 
            SharedParserCache.Atn, 
            SharedParserCache.DecisionToDfa, 
            SharedParserCache.ContextCache));
        return parser;
    }

    public bool Return(SqlBaseParser parser)
    {
        parser.Reset();
        return true;
    }
}
