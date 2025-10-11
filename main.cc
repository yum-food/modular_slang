#include <filesystem>
#include <cctype>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include <slang.h>
#include <slang-com-ptr.h>

namespace fs = std::filesystem;

using ::slang::CompilerOptionEntry;
using ::slang::CompilerOptionName;
using ::slang::createGlobalSession;
using ::slang::DeclReflection;
using ::slang::FunctionReflection;
using ::slang::IBlob;
using ::slang::ICompileRequest;
using ::slang::IGlobalSession;
using ::slang::IModule;
using ::slang::ISession;
using ::slang::SessionDesc;
using ::slang::TargetDesc;

template <typename T>
using ComPtr = ::Slang::ComPtr<T>;

// Print any diagnostics carried by a Slang blob with optional context information.
void printDiagnostics(const char* context, IBlob* diagnostics)
{
    if (!diagnostics)
    {
        return;
    }

    std::size_t size = diagnostics->getBufferSize();
    if (size == 0)
    {
        return;
    }

    std::string_view text(static_cast<const char*>(diagnostics->getBufferPointer()), size);
    if (!text.empty() && text.back() == '\0')
    {
        text.remove_suffix(1);
    }

    if (text.empty())
    {
        return;
    }

    if (context && *context)
    {
        std::cerr << context << " diagnostics:" << std::endl;
    }

    std::cerr.write(text.data(), text.size());
    if (text.back() != '\n')
    {
        std::cerr << std::endl;
    }
}

// Helper to check Slang API results and surface diagnostic details when available.
void checkResult(const char* context, SlangResult res, IBlob* diagnostics = nullptr)
{
    printDiagnostics(context, diagnostics);

    if (SLANG_FAILED(res))
    {
        std::cerr << (context && *context ? context : "Slang call")
                  << " failed with SlangResult " << res
                  << " (0x" << std::hex << res << std::dec << ')' << std::endl;
        exit(1);
    }
}

bool writeTextFile(const fs::path& path, std::string_view contents)
{
    std::ofstream file(path, std::ios::binary);
    if (!file)
    {
        std::cerr << "Warning: Failed to open " << path << " for writing." << std::endl;
        return false;
    }

    file.write(contents.data(), static_cast<std::streamsize>(contents.size()));
    file.close();

    if (!file)
    {
        std::cerr << "Warning: Failed to write " << path << std::endl;
        return false;
    }

    return true;
}

void addCompilerOption(std::vector<CompilerOptionEntry>& options, CompilerOptionName name)
{
    CompilerOptionEntry entry = {};
    entry.name = name;
    entry.value.intValue0 = 1;
    options.push_back(entry);
}

struct FunctionInfo
{
    std::string name;
};

struct IncludeGuardInfo
{
    bool present = false;
    std::string macro;
    std::string ifndefLine;
    std::string defineLine;
    std::string endifLine;
};

std::string trim(std::string_view text)
{
    std::size_t start = 0;
    std::size_t end = text.size();

    while (start < end && std::isspace(static_cast<unsigned char>(text[start])))
    {
        ++start;
    }

    while (end > start && std::isspace(static_cast<unsigned char>(text[end - 1])))
    {
        --end;
    }

    return std::string(text.substr(start, end - start));
}

bool isTopLevelFunction(DeclReflection* functionDecl)
{
    if (!functionDecl)
    {
        return false;
    }

    using Kind = DeclReflection::Kind;
    for (DeclReflection* parent = functionDecl->getParent(); parent;
         parent = parent->getParent())
    {
        switch (parent->getKind())
        {
        case Kind::Module:
        case Kind::Namespace:
            return true;
        case Kind::Generic:
            continue;
        default:
            return false;
        }
    }

    return false;
}

// Recursively gather function declarations defined in the supplied Slang module.
void collectFunctionInfos(
    DeclReflection* decl,
    std::vector<FunctionInfo>& functions,
    std::unordered_set<std::string>& seenNames)
{
    if (!decl)
    {
        return;
    }

    using Kind = DeclReflection::Kind;

    switch (decl->getKind())
    {
    case Kind::Func:
        if (auto* functionReflection = decl->asFunction())
        {
            if (const char* name = functionReflection->getName())
            {
                // Heuristic: functions that don't start with underscore are considered public
                // (Slang convention: private/internal functions typically start with _)
                bool isPublic = name[0] != '_';

                if (*name && seenNames.insert(name).second && isTopLevelFunction(decl) && isPublic)
                {
                    std::cerr << "Discovered entry point: " << name << std::endl;
                    functions.push_back({name});
                }
            }
        }
        break;
    case Kind::Generic:
        if (auto* genericDecl = decl->asGeneric())
        {
            collectFunctionInfos(
                genericDecl->getInnerDecl(),
                functions,
                seenNames);
        }
        break;
    default:
        break;
    }

    for (auto* child : decl->getChildren())
    {
        collectFunctionInfos(child, functions, seenNames);
    }
}

IncludeGuardInfo detectIncludeGuard(const fs::path& sourcePath)
{
    IncludeGuardInfo info;

    std::ifstream input(sourcePath);
    if (!input)
    {
        return info;
    }

    std::vector<std::string> lines;
    std::string line;
    while (std::getline(input, line))
    {
        lines.push_back(line);
    }

    std::size_t ifndefIndex = std::numeric_limits<std::size_t>::max();
    for (std::size_t i = 0; i < lines.size(); ++i)
    {
        std::string trimmed = trim(lines[i]);
        if (trimmed.rfind("#ifndef", 0) == 0)
        {
            std::istringstream stream(trimmed);
            std::string directive;
            std::string macro;
            stream >> directive >> macro;
            if (!macro.empty())
            {
                info.macro = macro;
                info.ifndefLine = lines[i];
                ifndefIndex = i;
            }
            break;
        }
    }

    if (info.macro.empty())
    {
        return info;
    }

    for (std::size_t i = ifndefIndex + 1; i < lines.size(); ++i)
    {
        std::string trimmed = trim(lines[i]);
        if (trimmed.rfind("#define", 0) == 0)
        {
            std::istringstream stream(trimmed);
            std::string directive;
            std::string macro;
            stream >> directive >> macro;
            if (macro == info.macro)
            {
                info.defineLine = lines[i];
                break;
            }
        }
    }

    if (info.defineLine.empty())
    {
        info = IncludeGuardInfo{};
        return info;
    }

    for (std::size_t i = lines.size(); i-- > 0;)
    {
        std::string trimmed = trim(lines[i]);
        if (trimmed.rfind("#endif", 0) == 0)
        {
            info.endifLine = lines[i];
            break;
        }
    }

    if (info.endifLine.empty())
    {
        info = IncludeGuardInfo{};
        return info;
    }

    info.present = true;
    return info;
}

int main(int argc, char** argv)
{
    if (argc < 2) {
        std::cerr << "Usage: " << (argc > 0 ? argv[0] : "modular_slang") << " <module.slang>" << std::endl;
        return 1;
    }
    fs::path modulePath = fs::absolute(argv[1]);
    if (!fs::exists(modulePath)) {
        std::cerr << "Module not found: " << modulePath << std::endl;
        return 1;
    }
    if (modulePath.extension() != ".slang") {
        std::cerr << "Expected a .slang file: " << modulePath << std::endl;
        return 1;
    }

    std::string moduleName = modulePath.stem().string();
    std::string searchPath = modulePath.has_parent_path()
        ? modulePath.parent_path().string()
        : fs::current_path().string();

    fs::path outputPath = modulePath;
    outputPath.replace_extension(".hlsl");

    // Create session
    ComPtr<IGlobalSession> globalSession;
    checkResult("createGlobalSession", createGlobalSession(globalSession.writeRef()));

    // Configure session and target
    TargetDesc targetDesc = {};
    targetDesc.format = SLANG_HLSL;
    targetDesc.profile = globalSession->findProfile("lib_6_6");
    targetDesc.flags = SLANG_TARGET_FLAG_GENERATE_WHOLE_PROGRAM;

    std::vector<CompilerOptionEntry> options;
    addCompilerOption(options, CompilerOptionName::DisableNonEssentialValidations);
    addCompilerOption(options, CompilerOptionName::NoHLSLBinding);
    addCompilerOption(options, CompilerOptionName::NoMangle);
    addCompilerOption(options, CompilerOptionName::NoHLSLPackConstantBufferElements);
    addCompilerOption(options, CompilerOptionName::NoEntryPointUniformParamTransform);

    std::vector<CompilerOptionEntry> targetOptions(options);
    targetDesc.compilerOptionEntries = targetOptions.data();
    targetDesc.compilerOptionEntryCount = static_cast<uint32_t>(targetOptions.size());

    SessionDesc sessionDesc = {};
    sessionDesc.targets = &targetDesc;
    sessionDesc.targetCount = 1;
    const char* searchPaths[] = { searchPath.c_str() };
    sessionDesc.searchPaths = searchPaths;
    sessionDesc.searchPathCount = 1;

    std::vector<CompilerOptionEntry> sessionOptions(options);
    sessionDesc.compilerOptionEntries = sessionOptions.data();
    sessionDesc.compilerOptionEntryCount = static_cast<uint32_t>(sessionOptions.size());

    ComPtr<ISession> session;
    checkResult("IGlobalSession::createSession",
        globalSession->createSession(sessionDesc, session.writeRef()));

    // Load the "module" aka the library
    ComPtr<IModule> libraryModule;
    {
        ComPtr<IBlob> diagnosticsBlob;
        libraryModule = session->loadModule(moduleName.c_str(), diagnosticsBlob.writeRef());
        const std::string diagnosticsContext = "loadModule: " + moduleName;
        printDiagnostics(diagnosticsContext.c_str(), diagnosticsBlob);
        if (!libraryModule)
        {
            std::cerr << "Failed to load module '" << moduleName << "'." << std::endl;
            return 1;
        }
    }

    // Discover top-level functions to treat as entry points
    std::vector<FunctionInfo> functions;
    std::unordered_set<std::string> seenNames;
    DeclReflection* moduleReflection = libraryModule->getModuleReflection();
    if (!moduleReflection) {
        std::cerr << "Failed to retrieve reflection data for module '" << moduleName << "'."
                  << std::endl;
        return 1;
    }
    collectFunctionInfos(moduleReflection, functions, seenNames);
    if (functions.empty()) {
        std::cerr << "No functions found in module '" << moduleName << "'." << std::endl;
        return 1;
    }

    // Compile
    ComPtr<ICompileRequest> compileRequest;
    checkResult(
        "ISession::createCompileRequest",
        session->createCompileRequest(compileRequest.writeRef()));

    compileRequest->setCodeGenTarget(SLANG_HLSL);
    compileRequest->setTargetProfile(0, targetDesc.profile);
    compileRequest->setTargetFlags(0, SLANG_TARGET_FLAG_GENERATE_WHOLE_PROGRAM);
    compileRequest->setMatrixLayoutMode(SLANG_MATRIX_LAYOUT_ROW_MAJOR);
    compileRequest->setLineDirectiveMode(SLANG_LINE_DIRECTIVE_MODE_NONE);

    compileRequest->addSearchPath(searchPath.c_str());

    const int translationUnitIndex = compileRequest->addTranslationUnit(
        SLANG_SOURCE_LANGUAGE_SLANG,
        moduleName.c_str());
    compileRequest->addTranslationUnitSourceFile(
        translationUnitIndex,
        modulePath.string().c_str());

    for (const FunctionInfo& func : functions)
    {
        const int entryPointIndex = compileRequest->addEntryPoint(
            translationUnitIndex,
            func.name.c_str(),
            SLANG_STAGE_DISPATCH);
        if (entryPointIndex < 0)
        {
            std::cerr << "Failed to register entry point '" << func.name << "'." << std::endl;
            return 1;
        }
    }

    SlangResult compileResult = compileRequest->compile();
    ComPtr<IBlob> compileDiagnostics;
    compileRequest->getDiagnosticOutputBlob(compileDiagnostics.writeRef());
    checkResult("ICompileRequest::compile", compileResult, compileDiagnostics);

    ComPtr<IBlob> targetCodeBlob;
    checkResult(
        "ICompileRequest::getTargetCodeBlob",
        compileRequest->getTargetCodeBlob(0, targetCodeBlob.writeRef()));

    if (!targetCodeBlob || targetCodeBlob->getBufferSize() == 0)
    {
        std::cerr << "No HLSL was generated for module '" << moduleName << "'." << std::endl;
        return 1;
    }

    std::string hlslSource(
        static_cast<const char*>(targetCodeBlob->getBufferPointer()),
        static_cast<std::size_t>(targetCodeBlob->getBufferSize()));

    fs::path rawOutputPath = outputPath;
    rawOutputPath.replace_extension(".raw.hlsl");
    writeTextFile(rawOutputPath, hlslSource);

    std::string finalHlsl = hlslSource;

    IncludeGuardInfo includeGuard = detectIncludeGuard(modulePath);
    if (includeGuard.present)
    {
        const std::string guardIfndefToken = "#ifndef " + includeGuard.macro;
        const std::string guardDefineToken = "#define " + includeGuard.macro;
        const bool alreadyGuarded =
            finalHlsl.find(guardIfndefToken) != std::string::npos &&
            finalHlsl.find(guardDefineToken) != std::string::npos;

        if (!alreadyGuarded)
        {
            std::string body = finalHlsl;
            if (!body.empty() && body.back() != '\n')
            {
                body += '\n';
            }

            std::ostringstream wrapped;
            wrapped << includeGuard.ifndefLine << '\n';
            wrapped << includeGuard.defineLine << '\n';
            wrapped << '\n';
            wrapped << body;
            if (!body.empty() && body.back() != '\n')
            {
                wrapped << '\n';
            }
            wrapped << includeGuard.endifLine;
            if (!includeGuard.endifLine.empty() && includeGuard.endifLine.back() != '\n')
            {
                wrapped << '\n';
            }

            finalHlsl = wrapped.str();
        }
    }

    // 6. Write HLSL output to a sibling .hlsl file
    if (!writeTextFile(outputPath, finalHlsl))
    {
        return 1;
    }

    std::cerr << "Generated HLSL written to " << outputPath << std::endl;

    return 0;
}
