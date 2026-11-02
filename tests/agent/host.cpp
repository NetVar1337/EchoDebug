// Test host for agent/echo_debug.as: compiles the agent with the real AngelScript engine against
// script mocks of Echo's API (echo_mock.as), then runs every function in namespace `tests`.
//
// Usage: agent_test <echo_mock.as> <echo_debug.as> <tests.as>...
// Exit code: 0 all tests passed, 1 test failures, 2 build/setup error.
#include <angelscript.h>
#include "scriptarray/scriptarray.h"
#include "scriptbuilder/scriptbuilder.h"
#include "scriptmath/scriptmath.h"
#include "scriptstdstring/scriptstdstring.h"

#include <cstdio>
#include <cstring>
#include <string>

static int g_failures = 0;   // check() failures in the running test

static const char* base_name(const char* path)
{
    const char* slash = std::strrchr(path ? path : "?", '/');
    return slash ? slash + 1 : (path ? path : "?");
}

static void message_cb(const asSMessageInfo* m, void*)
{
    const char* kind = m->type == asMSGTYPE_ERROR ? "error" : m->type == asMSGTYPE_WARNING ? "warning" : "info";
    std::printf("%s:%d:%d: %s: %s\n", base_name(m->section), m->row, m->col, kind, m->message);
}

// check(cond, what): records a failure with the script location instead of aborting the test.
static void check(bool ok, const std::string& what)
{
    if (ok) return;
    g_failures++;
    asIScriptContext* ctx = asGetActiveContext();
    const char* section = "?";
    int line = ctx ? ctx->GetLineNumber(0, nullptr, &section) : 0;
    std::printf("    FAIL %s:%d: %s\n", base_name(section), line, what.c_str());
}

static void print(const std::string& s) { std::printf("    %s\n", s.c_str()); }

static bool run(asIScriptContext* ctx, asIScriptFunction* fn, std::string& err)
{
    ctx->Prepare(fn);
    int r = ctx->Execute();
    if (r == asEXECUTION_FINISHED) return true;
    if (r == asEXECUTION_EXCEPTION)
    {
        const char* section = "?";
        int line = ctx->GetExceptionLineNumber(nullptr, &section);
        err = std::string(base_name(section)) + ":" + std::to_string(line) + ": script exception: " + ctx->GetExceptionString() +
              " (in " + ctx->GetExceptionFunction()->GetDeclaration() + ")";
    }
    else err = "execution ended with code " + std::to_string(r);
    return false;
}

int main(int argc, char** argv)
{
    if (argc < 4)
    {
        std::fprintf(stderr, "usage: %s <echo_mock.as> <echo_debug.as> <tests.as>...\n", argv[0]);
        return 2;
    }
    asIScriptEngine* engine = asCreateScriptEngine();
    engine->SetMessageCallback(asFUNCTION(message_cb), nullptr, asCALL_CDECL);
    RegisterStdString(engine);
    RegisterScriptArray(engine, true);
    RegisterStdStringUtils(engine);
    RegisterScriptMath(engine);
    engine->RegisterGlobalFunction("void check(bool, const string &in)", asFUNCTION(check), asCALL_CDECL);
    engine->RegisterGlobalFunction("void print(const string &in)", asFUNCTION(print), asCALL_CDECL);

    CScriptBuilder builder;
    if (builder.StartNewModule(engine, "agent") < 0) return 2;
    for (int i = 1; i < argc; i++)
        if (builder.AddSectionFromFile(argv[i]) < 0) { std::fprintf(stderr, "cannot read %s\n", argv[i]); return 2; }
    if (builder.BuildModule() < 0) { std::fprintf(stderr, "build failed\n"); return 2; }

    asIScriptModule* mod = engine->GetModule("agent");
    asIScriptFunction* reset = mod->GetFunctionByDecl("void mock_reset()");
    asIScriptContext* ctx = engine->CreateContext();
    int passed = 0, failed = 0;
    for (asUINT i = 0; i < mod->GetFunctionCount(); i++)
    {
        asIScriptFunction* fn = mod->GetFunctionByIndex(i);
        if (std::string(fn->GetNamespace()) != "tests" || fn->GetParamCount() != 0) continue;
        g_failures = 0;
        std::string err;
        bool ok = (!reset || run(ctx, reset, err)) && run(ctx, fn, err);
        if (!ok) std::printf("    %s\n", err.c_str());
        ok = ok && g_failures == 0;
        std::printf("%s %s\n", ok ? "ok  " : "FAIL", fn->GetName());
        (ok ? passed : failed)++;
    }
    ctx->Release();
    engine->ShutDownAndRelease();
    std::printf("\n%d passed, %d failed\n", passed, failed);
    return failed || passed == 0 ? 1 : 0;
}
