namespace TrinoSqlEngine;

using Antlr4.Runtime.Atn;

public partial class SqlBaseParser
{
    public void SetInterpreter(ParserATNSimulator interpreter)
    {
        Interpreter = interpreter;
    }
}
