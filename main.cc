#include <filesystem>
#include <cctype>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <slang.h>
#include <slang-com-ptr.h>

// Print any diagnostics carried by a Slang blob with optional context information.
void printDiagnostics(const char* context, slang::IBlob* diagnostics)
{
    if (!diagnostics)
    {
        return;
    }

    size_t size = diagnostics->getBufferSize();
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
void checkResult(const char* context, SlangResult res, slang::IBlob* diagnostics = nullptr)
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

struct ParameterInfo
{
    std::string name;
    std::string typeName;
};

struct FunctionInfo
{
    std::string name;
    std::string returnType;
    std::vector<ParameterInfo> parameters;
};

std::string trim(std::string_view text)
{
    size_t start = 0;
    size_t end = text.size();

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

std::string getTypeName(slang::TypeReflection* type)
{
    if (!type)
    {
        return {};
    }

    using Kind = slang::TypeReflection::Kind;
    using Scalar = slang::TypeReflection::ScalarType;

    auto scalarToString = [](Scalar scalar) -> std::string
    {
        switch (scalar)
        {
        case Scalar::Float16:
        case Scalar::Float32:
        case Scalar::Float64:
            return "float";
        case Scalar::Int8:
        case Scalar::Int16:
        case Scalar::Int32:
        case Scalar::Int64:
            return "int";
        case Scalar::UInt8:
        case Scalar::UInt16:
        case Scalar::UInt32:
        case Scalar::UInt64:
            return "uint";
        case Scalar::Bool:
            return "bool";
        default:
            return {};
        }
    };

    switch (type->getKind())
    {
    case Kind::Scalar:
        if (const std::string base = scalarToString(type->getScalarType()); !base.empty())
        {
            return base;
        }
        break;
    case Kind::Vector:
    {
        const std::string elementTypeName = getTypeName(type->getElementType());
        const size_t elementCount = type->getElementCount();
        if (!elementTypeName.empty() && elementCount > 0)
        {
            return elementTypeName + std::to_string(elementCount);
        }
        break;
    }
    case Kind::Matrix:
    {
        const std::string elementTypeName = getTypeName(type->getElementType());
        const unsigned rows = type->getRowCount();
        const unsigned cols = type->getColumnCount();
        if (!elementTypeName.empty() && rows > 0 && cols > 0)
        {
            return elementTypeName + std::to_string(rows) + "x" + std::to_string(cols);
        }
        break;
    }
    default:
        break;
    }

    if (const char* simpleName = type->getName())
    {
        if (simpleName[0] != '\0')
        {
            return simpleName;
        }
    }

    Slang::ComPtr<ISlangBlob> fullNameBlob;
    if (SLANG_SUCCEEDED(type->getFullName(fullNameBlob.writeRef())) && fullNameBlob &&
        fullNameBlob->getBufferSize() > 0)
    {
        const char* buffer = static_cast<const char*>(fullNameBlob->getBufferPointer());
        std::string fullName(buffer, buffer + fullNameBlob->getBufferSize());

        auto parseTemplateType = [&](std::string_view name) -> std::string
        {
            if (name.substr(0, 7) == "vector<")
            {
                size_t commaPos = name.find(',');
                size_t endPos = name.rfind('>');
                if (commaPos != std::string_view::npos && endPos != std::string_view::npos &&
                    commaPos + 1 < endPos)
                {
                    std::string base = trim(name.substr(7, commaPos - 7));
                    std::string count = trim(name.substr(commaPos + 1, endPos - commaPos - 1));
                    return base + count;
                }
            }
            if (name.substr(0, 7) == "matrix<")
            {
                size_t firstComma = name.find(',');
                size_t secondComma = name.find(',', firstComma + 1);
                size_t endPos = name.rfind('>');
                if (firstComma != std::string_view::npos && secondComma != std::string_view::npos &&
                    endPos != std::string_view::npos)
                {
                    std::string base = trim(name.substr(7, firstComma - 7));
                    std::string rows = trim(name.substr(firstComma + 1, secondComma - firstComma - 1));
                    std::string cols = trim(name.substr(secondComma + 1, endPos - secondComma - 1));
                    return base + rows + "x" + cols;
                }
            }
            return std::string(name);
        };

        return parseTemplateType(fullName);
    }

    return {};
}

bool isTopLevelFunction(slang::DeclReflection* functionDecl)
{
    if (!functionDecl)
    {
        return false;
    }

    using Kind = slang::DeclReflection::Kind;
    for (slang::DeclReflection* parent = functionDecl->getParent(); parent;
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
    slang::DeclReflection* decl,
    std::vector<FunctionInfo>& functions,
    std::unordered_set<std::string>& seenNames)
{
    if (!decl)
    {
        return;
    }

    using Kind = slang::DeclReflection::Kind;

    switch (decl->getKind())
    {
    case Kind::Func:
        if (auto* functionReflection = decl->asFunction())
        {
            if (const char* name = functionReflection->getName())
            {
                if (*name && seenNames.insert(name).second && isTopLevelFunction(decl))
                {
                    FunctionInfo info;
                    info.name = name;

                    if (slang::TypeReflection* returnType = functionReflection->getReturnType())
                    {
                        info.returnType = getTypeName(returnType);
                    }
                    if (info.returnType.empty())
                    {
                        info.returnType = "void";
                    }

                    const unsigned paramCount = functionReflection->getParameterCount();
                    info.parameters.reserve(paramCount);
                    for (unsigned i = 0; i < paramCount; ++i)
                    {
                        slang::VariableReflection* paramReflection =
                            functionReflection->getParameterByIndex(i);
                        ParameterInfo paramInfo;
                        if (auto* typeReflection = paramReflection->getType())
                        {
                            paramInfo.typeName = getTypeName(typeReflection);
                        }
                        if (paramInfo.typeName.empty())
                        {
                            paramInfo.typeName = "auto";
                        }
                        if (const char* paramName = paramReflection->getName())
                        {
                            paramInfo.name = paramName;
                        }
                        if (paramInfo.name.empty())
                        {
                            paramInfo.name = "param" + std::to_string(i);
                        }
                        info.parameters.push_back(std::move(paramInfo));
                    }

                    functions.push_back(std::move(info));
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

struct EntryPointField
{
    int bufferIndex = 0;
    std::string fieldName;
    std::string baseName;
};

std::string rewriteHLSLWithWrappers(
    const std::string& originalHlsl,
    const std::vector<FunctionInfo>& functions)
{
    std::string result = originalHlsl;

    std::unordered_map<int, std::vector<EntryPointField>> bufferIndexToFields;
    std::unordered_map<std::string, std::vector<EntryPointField>> baseNameToFields;

    const std::string structPrefix = "struct EntryPointParams_";
    size_t searchPos = 0;
    while (true)
    {
        size_t structPos = result.find(structPrefix, searchPos);
        if (structPos == std::string::npos)
        {
            break;
        }

        size_t indexPos = structPos + structPrefix.size();
        size_t indexEnd = indexPos;
        while (indexEnd < result.size() && std::isdigit(static_cast<unsigned char>(result[indexEnd])))
        {
            ++indexEnd;
        }
        if (indexEnd == indexPos)
        {
            searchPos = indexEnd;
            continue;
        }

        int bufferIndex = std::stoi(result.substr(indexPos, indexEnd - indexPos));

        size_t braceOpen = result.find('{', indexEnd);
        if (braceOpen == std::string::npos)
        {
            break;
        }
        size_t braceClose = result.find("};", braceOpen);
        if (braceClose == std::string::npos)
        {
            break;
        }

        size_t fieldPos = braceOpen + 1;
        while (fieldPos < braceClose)
        {
            size_t semicolon = result.find(';', fieldPos);
            if (semicolon == std::string::npos || semicolon > braceClose)
            {
                break;
            }

            std::string line = trim(std::string_view(result).substr(fieldPos, semicolon - fieldPos));
            if (!line.empty())
            {
                size_t lastSpace = line.find_last_of(" \t");
                if (lastSpace != std::string::npos && lastSpace + 1 < line.size())
                {
                    std::string fieldName = line.substr(lastSpace + 1);
                    size_t bracketPos = fieldName.find('[');
                    if (bracketPos != std::string::npos)
                    {
                        fieldName = fieldName.substr(0, bracketPos);
                    }

                    std::string baseName = fieldName;
                    size_t underscorePos = baseName.rfind('_');
                    if (underscorePos != std::string::npos)
                    {
                        baseName = baseName.substr(0, underscorePos);
                    }

                    EntryPointField field{bufferIndex, fieldName, baseName};
                    bufferIndexToFields[bufferIndex].push_back(field);
                    baseNameToFields[baseName].push_back(field);
                }
            }

            fieldPos = semicolon + 1;
        }

        searchPos = braceClose;
    }

    const std::string attributeToken = "[shader(\"dispatch\")]export";
    size_t searchFrom = 0;
    for (const FunctionInfo& func : functions)
    {
        size_t attrPos = result.find(attributeToken, searchFrom);
        if (attrPos != std::string::npos)
        {
            size_t attrEnd = attrPos + attributeToken.size();
            if (attrEnd < result.size() && result[attrEnd] == '\r')
            {
                ++attrEnd;
            }
            if (attrEnd < result.size() && result[attrEnd] == '\n')
            {
                ++attrEnd;
            }
            result.erase(attrPos, attrEnd - attrPos);
            searchFrom = attrPos;
        }

        size_t namePos = result.find(func.name + "(", searchFrom);
        if (namePos == std::string::npos)
        {
            namePos = result.find(func.name + "(");
        }
        if (namePos != std::string::npos)
        {
            const std::string entryName = "__slang_entry_" + func.name;
            result.replace(namePos, func.name.size(), entryName);
            searchFrom = namePos + entryName.size();
        }
    }

    std::ostringstream wrapperBuilder;
    wrapperBuilder << "\n";

    for (size_t functionIndex = 0; functionIndex < functions.size(); ++functionIndex)
    {
        const FunctionInfo& func = functions[functionIndex];
        const std::string entryName = "__slang_entry_" + func.name;

        std::string parameterList;
        for (size_t i = 0; i < func.parameters.size(); ++i)
        {
            if (i > 0)
            {
                parameterList += ", ";
            }
            parameterList += func.parameters[i].typeName + " " + func.parameters[i].name;
        }

        wrapperBuilder << func.returnType << " " << func.name << "(" << parameterList << ")\n";
        wrapperBuilder << "{\n";

        std::unordered_set<std::string> emittedAssignments;

        for (size_t paramIndex = 0; paramIndex < func.parameters.size(); ++paramIndex)
        {
            const ParameterInfo& param = func.parameters[paramIndex];

            auto baseIt = baseNameToFields.find(param.name);
            if (baseIt != baseNameToFields.end())
            {
                for (const EntryPointField& field : baseIt->second)
                {
                    std::string assignment =
                        "    entryPointParams_" + std::to_string(field.bufferIndex) + "." +
                        field.fieldName + " = " + param.name + ";\n";
                    if (emittedAssignments.insert(assignment).second)
                    {
                        wrapperBuilder << assignment;
                    }
                }
            }

            auto bufferIt = bufferIndexToFields.find(static_cast<int>(functionIndex));
            if (bufferIt != bufferIndexToFields.end() && paramIndex < bufferIt->second.size())
            {
                const EntryPointField& field = bufferIt->second[paramIndex];
                std::string assignment =
                    "    entryPointParams_" + std::to_string(field.bufferIndex) + "." +
                    field.fieldName + " = " + param.name + ";\n";
                if (emittedAssignments.insert(assignment).second)
                {
                    wrapperBuilder << assignment;
                }
            }
        }

        if (func.returnType == "void")
        {
            wrapperBuilder << "    " << entryName << "();\n";
            wrapperBuilder << "    return;\n";
        }
        else
        {
            wrapperBuilder << "    return " << entryName << "();\n";
        }

        wrapperBuilder << "}\n\n";
    }

    const std::string wrappers = wrapperBuilder.str();
    if (!wrappers.empty())
    {
        const size_t endifPos = result.rfind("#endif");
        const size_t ifndefPos = result.find("#ifndef");
        const size_t definePos = result.find("#define", ifndefPos != std::string::npos ? ifndefPos : 0);

        const bool hasGuard =
            ifndefPos != std::string::npos && definePos != std::string::npos &&
            endifPos != std::string::npos && ifndefPos < definePos && definePos < endifPos;

        if (hasGuard)
        {
            result.insert(endifPos, wrappers);
        }
        else
        {
            result += wrappers;
        }
    }

    return result;
}

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        std::cerr << "Usage: " << (argc > 0 ? argv[0] : "modular_slang") << " <module.slang>" << std::endl;
        return 1;
    }

    std::filesystem::path modulePath = std::filesystem::absolute(argv[1]);
    if (!std::filesystem::exists(modulePath))
    {
        std::cerr << "Module not found: " << modulePath << std::endl;
        return 1;
    }

    if (modulePath.extension() != ".slang")
    {
        std::cerr << "Expected a .slang file: " << modulePath << std::endl;
        return 1;
    }

    std::string moduleName = modulePath.stem().string();
    std::string searchPath = modulePath.has_parent_path()
        ? modulePath.parent_path().string()
        : std::filesystem::current_path().string();

    std::filesystem::path outputPath = modulePath;
    outputPath.replace_extension(".hlsl");

    // 1. Session Creation
    Slang::ComPtr<slang::IGlobalSession> globalSession;
    checkResult("slang::createGlobalSession", slang::createGlobalSession(globalSession.writeRef()));

    // 2. Target Configuration
    slang::TargetDesc targetDesc = {};
    targetDesc.format = SLANG_HLSL;
    targetDesc.profile = globalSession->findProfile("lib_6_6");
    targetDesc.flags = SLANG_TARGET_FLAG_GENERATE_WHOLE_PROGRAM;

    std::vector<slang::CompilerOptionEntry> targetOptions;
    {
        slang::CompilerOptionEntry entry = {};
        entry.name = slang::CompilerOptionName::NoHLSLBinding;
        entry.value.intValue0 = 1;
        targetOptions.push_back(entry);
    }
    {
        slang::CompilerOptionEntry entry = {};
        entry.name = slang::CompilerOptionName::NoHLSLPackConstantBufferElements;
        entry.value.intValue0 = 1;
        targetOptions.push_back(entry);
    }
    targetDesc.compilerOptionEntries = targetOptions.data();
    targetDesc.compilerOptionEntryCount = static_cast<uint32_t>(targetOptions.size());

    slang::SessionDesc sessionDesc = {};
    sessionDesc.targets = &targetDesc;
    sessionDesc.targetCount = 1;
    const char* searchPaths[] = { searchPath.c_str() };
    sessionDesc.searchPaths = searchPaths;
    sessionDesc.searchPathCount = 1;

    std::vector<slang::CompilerOptionEntry> sessionOptions;
    {
        slang::CompilerOptionEntry entry = {};
        entry.name = slang::CompilerOptionName::NoMangle;
        entry.value.intValue0 = 1;
        sessionOptions.push_back(entry);
    }
    {
        slang::CompilerOptionEntry entry = {};
        entry.name = slang::CompilerOptionName::DisableNonEssentialValidations;
        entry.value.intValue0 = 1;
        sessionOptions.push_back(entry);
    }
    sessionDesc.compilerOptionEntries = sessionOptions.data();
    sessionDesc.compilerOptionEntryCount = static_cast<uint32_t>(sessionOptions.size());

    Slang::ComPtr<slang::ISession> session;
    checkResult("IGlobalSession::createSession", globalSession->createSession(sessionDesc, session.writeRef()));

    // 3. Module Loading (from the supplied Slang source file)
    Slang::ComPtr<slang::IModule> libraryModule;
    {
        Slang::ComPtr<slang::IBlob> diagnosticsBlob;
        libraryModule = session->loadModule(moduleName.c_str(), diagnosticsBlob.writeRef());
        const std::string diagnosticsContext = "loadModule: " + moduleName;
        printDiagnostics(diagnosticsContext.c_str(), diagnosticsBlob);
        if (!libraryModule)
        {
            std::cerr << "Failed to load module '" << moduleName << "'." << std::endl;
            return 1;
        }
    }
    // 4. Discover top-level functions to treat as entry points
    std::vector<FunctionInfo> functions;
    std::unordered_set<std::string> seenNames;
    slang::DeclReflection* moduleReflection = libraryModule->getModuleReflection();
    if (!moduleReflection)
    {
        std::cerr << "Failed to retrieve reflection data for module '" << moduleName << "'."
                  << std::endl;
        return 1;
    }
    collectFunctionInfos(moduleReflection, functions, seenNames);

    if (functions.empty())
    {
        std::cerr << "No functions found in module '" << moduleName << "'." << std::endl;
        return 1;
    }

    // 5. Compile the translation unit with whole-program emission
    Slang::ComPtr<slang::ICompileRequest> compileRequest;
    checkResult(
        "ISession::createCompileRequest",
        session->createCompileRequest(compileRequest.writeRef()));

    compileRequest->setCodeGenTarget(SLANG_HLSL);
    compileRequest->setTargetProfile(0, targetDesc.profile);
    compileRequest->setTargetFlags(0, SLANG_TARGET_FLAG_GENERATE_WHOLE_PROGRAM);

    SlangCompileFlags compileFlags = compileRequest->getCompileFlags();
    compileFlags |= SLANG_COMPILE_FLAG_NO_MANGLING;
    compileRequest->setCompileFlags(compileFlags);

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
    Slang::ComPtr<slang::IBlob> compileDiagnostics;
    compileRequest->getDiagnosticOutputBlob(compileDiagnostics.writeRef());
    checkResult("ICompileRequest::compile", compileResult, compileDiagnostics);

    Slang::ComPtr<slang::IBlob> targetCodeBlob;
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
        static_cast<size_t>(targetCodeBlob->getBufferSize()));

    const std::string finalHlsl = rewriteHLSLWithWrappers(hlslSource, functions);

    // 6. Write HLSL output to a sibling .hlsl file
    std::ofstream outputFile(outputPath, std::ios::binary);
    if (!outputFile)
    {
        std::cerr << "Failed to open output path for writing: " << outputPath << std::endl;
        return 1;
    }

    outputFile.write(finalHlsl.data(), static_cast<std::streamsize>(finalHlsl.size()));
    outputFile.close();

    if (!outputFile)
    {
        std::cerr << "Failed to write HLSL output to " << outputPath << std::endl;
        return 1;
    }

    // Also stream to standard output to retain previous behavior
    std::cout.write(finalHlsl.data(), static_cast<std::streamsize>(finalHlsl.size()));
    if (finalHlsl.empty() || finalHlsl.back() != '\n')
    {
        std::cout << std::endl;
    }

    std::cerr << "Generated HLSL written to " << outputPath << std::endl;

    return 0;
}
