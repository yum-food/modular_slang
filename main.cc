#include <array>
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

#include "absl/status/status.h"
#include "absl/status/statusor.h"

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
void printDiagnostics(const char* context, IBlob* diagnostics) {
  if (!diagnostics) {
    return;
  }

  std::size_t size = diagnostics->getBufferSize();
  if (size == 0) {
    return;
  }

  std::string_view text(static_cast<const char*>(diagnostics->getBufferPointer()), size);
  if (!text.empty() && text.back() == '\0') {
    text.remove_suffix(1);
  }

  if (text.empty()) {
    return;
  }

  if (context && *context) {
    std::cerr << context << " diagnostics:" << std::endl;
  }

  std::cerr.write(text.data(), text.size());
  if (text.back() != '\n') {
    std::cerr << std::endl;
  }
}

// Helper to convert Slang API results into absl::Status values.
absl::Status checkSlangResult(const char* context, SlangResult res, IBlob* diagnostics = nullptr) {
  printDiagnostics(context, diagnostics);

  if (SLANG_FAILED(res)) {
    std::ostringstream message;
    message << (context && *context ? context : "Slang call")
    << " failed with SlangResult " << res
    << " (0x" << std::hex << res << std::dec << ')';
    return absl::InternalError(message.str());
  }

  return absl::OkStatus();
}

absl::Status writeTextFile(const fs::path& path, std::string_view contents) {
  std::ofstream file(path, std::ios::binary);
  if (!file) {
    std::ostringstream msg;
    msg << "Failed to open " << path << " for writing.";
    return absl::InternalError(msg.str());
  }

  file.write(contents.data(), static_cast<std::streamsize>(contents.size()));
  file.close();

  if (!file) {
    std::ostringstream msg;
    msg << "Failed to write " << path;
    return absl::InternalError(msg.str());
  }

  return absl::OkStatus();
}

void addCompilerOption(std::vector<CompilerOptionEntry>& options, CompilerOptionName name) {
  CompilerOptionEntry entry = {};
  entry.name = name;
  entry.value.intValue0 = 1;
  options.push_back(entry);
}

struct FunctionInfo {
  std::string name;
};

struct IncludeGuardInfo {
  bool present = false;
  std::string macro;
  std::string ifndefLine;
  std::string defineLine;
  std::string endifLine;
};

struct ModuleRequest {
  fs::path modulePath;
  std::string moduleName;
  std::string searchPath;
  fs::path outputPath;
};

std::string trim(std::string_view text) {
  std::size_t start = 0;
  std::size_t end = text.size();

  while (start < end && std::isspace(static_cast<unsigned char>(text[start]))) {
    ++start;
  }

  while (end > start && std::isspace(static_cast<unsigned char>(text[end - 1]))) {
    --end;
  }

  return std::string(text.substr(start, end - start));
}

bool isTopLevelFunction(DeclReflection* functionDecl) {
  if (!functionDecl) {
    return false;
  }

  using Kind = DeclReflection::Kind;
  for (DeclReflection* parent = functionDecl->getParent(); parent;
      parent = parent->getParent()) {
    switch (parent->getKind()) {
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
    std::unordered_set<std::string>& seenNames) {
  if (!decl) {
    return;
  }

  using Kind = DeclReflection::Kind;

  switch (decl->getKind()) {
  case Kind::Func:
    if (auto* functionReflection = decl->asFunction()) {
      if (const char* name = functionReflection->getName()) {
        // Heuristic: functions that don't start with underscore are considered public
        // (Slang convention: private/internal functions typically start with _)
        bool isPublic = name[0] != '_';

        if (*name && seenNames.insert(name).second && isTopLevelFunction(decl) && isPublic) {
          std::cerr << "Discovered entry point: " << name << std::endl;
          functions.push_back({name});
        }
      }
    }
    break;
  case Kind::Generic:
    if (auto* genericDecl = decl->asGeneric()) {
      collectFunctionInfos(
          genericDecl->getInnerDecl(),
          functions,
          seenNames);
    }
    break;
  default:
    break;
  }

  for (auto* child : decl->getChildren()) {
    collectFunctionInfos(child, functions, seenNames);
  }
}

IncludeGuardInfo detectIncludeGuard(const fs::path& sourcePath) {
  IncludeGuardInfo info;

  std::ifstream input(sourcePath);
  if (!input) {
    return info;
  }

  std::vector<std::string> lines;
  std::string line;
  while (std::getline(input, line)) {
    lines.push_back(line);
  }

  std::size_t ifndefIndex = std::numeric_limits<std::size_t>::max();
  for (std::size_t i = 0; i < lines.size(); ++i) {
    std::string trimmed = trim(lines[i]);
    if (trimmed.rfind("#ifndef", 0) == 0) {
      std::istringstream stream(trimmed);
      std::string directive;
      std::string macro;
      stream >> directive >> macro;
      if (!macro.empty()) {
        info.macro = macro;
        info.ifndefLine = lines[i];
        ifndefIndex = i;
      }
      break;
    }
  }

  if (info.macro.empty()) {
    return info;
  }

  for (std::size_t i = ifndefIndex + 1; i < lines.size(); ++i) {
    std::string trimmed = trim(lines[i]);
    if (trimmed.rfind("#define", 0) == 0) {
      std::istringstream stream(trimmed);
      std::string directive;
      std::string macro;
      stream >> directive >> macro;
      if (macro == info.macro) {
        info.defineLine = lines[i];
        break;
      }
    }
  }

  if (info.defineLine.empty()) {
    info = IncludeGuardInfo{};
    return info;
  }

  for (std::size_t i = lines.size(); i-- > 0;) {
    std::string trimmed = trim(lines[i]);
    if (trimmed.rfind("#endif", 0) == 0) {
      info.endifLine = lines[i];
      break;
    }
  }

  if (info.endifLine.empty()) {
    info = IncludeGuardInfo{};
    return info;
  }

  info.present = true;
  return info;
}

absl::StatusOr<ModuleRequest> parseModuleRequest(int argc, char** argv) {
  const char* programName = (argc > 0 && argv) ? argv[0] : "modular_slang";

  if (argc < 2 || !argv) {
    std::ostringstream usage;
    usage << "Usage: " << programName << " <module.slang>";
    return absl::InvalidArgumentError(usage.str());
  }

  ModuleRequest request;
  request.modulePath = fs::absolute(argv[1]);

  if (!fs::exists(request.modulePath)) {
    std::ostringstream msg;
    msg << "Module not found: " << request.modulePath;
    return absl::NotFoundError(msg.str());
  }

  if (request.modulePath.extension() != ".slang") {
    std::ostringstream msg;
    msg << "Expected a .slang file: " << request.modulePath;
    return absl::InvalidArgumentError(msg.str());
  }

  request.moduleName = request.modulePath.stem().string();
  request.searchPath = request.modulePath.has_parent_path()
  ? request.modulePath.parent_path().string()
  : fs::current_path().string();
  request.outputPath = request.modulePath;
  request.outputPath.replace_extension(".hlsl");

  return request;
}

std::vector<CompilerOptionEntry> makeCommonOptions() {
  std::vector<CompilerOptionEntry> options;
  addCompilerOption(options, CompilerOptionName::DisableNonEssentialValidations);
  addCompilerOption(options, CompilerOptionName::NoHLSLBinding);
  addCompilerOption(options, CompilerOptionName::NoMangle);
  addCompilerOption(options, CompilerOptionName::NoHLSLPackConstantBufferElements);
  addCompilerOption(options, CompilerOptionName::NoEntryPointUniformParamTransform);
  return options;
}

void configureTargetDesc(
    IGlobalSession* globalSession,
    std::vector<CompilerOptionEntry>& targetOptions,
    TargetDesc& outDesc) {
  outDesc = {};
  outDesc.format = SLANG_HLSL;
  outDesc.profile = globalSession->findProfile("lib_6_6");
  outDesc.flags = SLANG_TARGET_FLAG_GENERATE_WHOLE_PROGRAM;
  outDesc.compilerOptionEntries = targetOptions.data();
  outDesc.compilerOptionEntryCount = static_cast<uint32_t>(targetOptions.size());
}

void configureSessionDesc(
    const TargetDesc& targetDesc,
    const ModuleRequest& request,
    std::vector<CompilerOptionEntry>& sessionOptions,
    std::array<const char*, 1>& searchPathStorage,
    SessionDesc& outDesc) {
  searchPathStorage[0] = request.searchPath.c_str();

  outDesc = {};
  outDesc.targets = &targetDesc;
  outDesc.targetCount = 1;
  outDesc.searchPaths = searchPathStorage.data();
  outDesc.searchPathCount = static_cast<uint32_t>(searchPathStorage.size());
  outDesc.compilerOptionEntries = sessionOptions.data();
  outDesc.compilerOptionEntryCount = static_cast<uint32_t>(sessionOptions.size());
}

absl::StatusOr<ComPtr<IModule>> loadSlangModule(ISession* session, const std::string& moduleName) {
  ComPtr<IModule> module;
  ComPtr<IBlob> diagnostics;
  module = session->loadModule(moduleName.c_str(), diagnostics.writeRef());

  const std::string context = "loadModule: " + moduleName;
  printDiagnostics(context.c_str(), diagnostics);

  if (!module) {
    std::ostringstream msg;
    msg << "Failed to load module '" << moduleName << "'.";
    return absl::InternalError(msg.str());
  }

  return module;
}

absl::StatusOr<std::vector<FunctionInfo>> collectEntryPoints(
    IModule* module,
    const std::string& moduleName) {
  std::vector<FunctionInfo> functions;
  std::unordered_set<std::string> seenNames;

  DeclReflection* moduleReflection = module ? module->getModuleReflection() : nullptr;
  if (!moduleReflection) {
    std::ostringstream msg;
    msg << "Failed to retrieve reflection data for module '"
    << moduleName << "'.";
    return absl::InternalError(msg.str());
  }

  collectFunctionInfos(moduleReflection, functions, seenNames);

  if (functions.empty()) {
    std::ostringstream msg;
    msg << "No functions found in module '" << moduleName << "'.";
    return absl::NotFoundError(msg.str());
  }

  return functions;
}

absl::StatusOr<ComPtr<ICompileRequest>> createCompileRequest(
    ISession* session,
    const ModuleRequest& request,
    const TargetDesc& targetDesc,
    const std::vector<FunctionInfo>& functions) {
  ComPtr<ICompileRequest> compileRequest;
  ABSL_RETURN_IF_ERROR(checkSlangResult(
      "ISession::createCompileRequest",
      session->createCompileRequest(compileRequest.writeRef())));

  compileRequest->setCodeGenTarget(SLANG_HLSL);
  compileRequest->setTargetProfile(0, targetDesc.profile);
  compileRequest->setTargetFlags(0, SLANG_TARGET_FLAG_GENERATE_WHOLE_PROGRAM);
  compileRequest->setMatrixLayoutMode(SLANG_MATRIX_LAYOUT_ROW_MAJOR);
  compileRequest->setLineDirectiveMode(SLANG_LINE_DIRECTIVE_MODE_NONE);

  compileRequest->addSearchPath(request.searchPath.c_str());

  const int translationUnitIndex = compileRequest->addTranslationUnit(
      SLANG_SOURCE_LANGUAGE_SLANG,
      request.moduleName.c_str());
  compileRequest->addTranslationUnitSourceFile(
      translationUnitIndex,
      request.modulePath.string().c_str());

  for (const FunctionInfo& func : functions) {
    const int entryPointIndex = compileRequest->addEntryPoint(
        translationUnitIndex,
        func.name.c_str(),
        SLANG_STAGE_DISPATCH);
    if (entryPointIndex < 0) {
      std::ostringstream msg;
      msg << "Failed to register entry point '" << func.name << "'.";
      return absl::InternalError(msg.str());
    }
  }

  return compileRequest;
}

absl::StatusOr<std::string> collectGeneratedHlsl(ICompileRequest* compileRequest, const std::string& moduleName) {
  SlangResult compileResult = compileRequest->compile();
  ComPtr<IBlob> diagnostics;
  compileRequest->getDiagnosticOutputBlob(diagnostics.writeRef());
  ABSL_RETURN_IF_ERROR(checkSlangResult("ICompileRequest::compile", compileResult, diagnostics.get()));

  ComPtr<IBlob> targetCodeBlob;
  ABSL_RETURN_IF_ERROR(checkSlangResult(
      "ICompileRequest::getTargetCodeBlob",
      compileRequest->getTargetCodeBlob(0, targetCodeBlob.writeRef())));

  if (!targetCodeBlob || targetCodeBlob->getBufferSize() == 0) {
    std::ostringstream msg;
    msg << "No HLSL was generated for module '" << moduleName << "'.";
    return absl::InternalError(msg.str());
  }

  return std::string(
      static_cast<const char*>(targetCodeBlob->getBufferPointer()),
      static_cast<std::size_t>(targetCodeBlob->getBufferSize()));
}

std::string applyIncludeGuard(const std::string& hlslSource, const IncludeGuardInfo& includeGuard) {
  if (!includeGuard.present) {
    return hlslSource;
  }

  const std::string guardIfndefToken = "#ifndef " + includeGuard.macro;
  const std::string guardDefineToken = "#define " + includeGuard.macro;
  const bool alreadyGuarded =
  hlslSource.find(guardIfndefToken) != std::string::npos &&
  hlslSource.find(guardDefineToken) != std::string::npos;

  if (alreadyGuarded) {
    return hlslSource;
  }

  std::string body = hlslSource;
  if (!body.empty() && body.back() != '\n') {
    body += '\n';
  }

  std::ostringstream wrapped;
  wrapped << includeGuard.ifndefLine << '\n';
  wrapped << includeGuard.defineLine << '\n';
  wrapped << '\n';
  wrapped << body;
  if (!body.empty() && body.back() != '\n') {
    wrapped << '\n';
  }
  wrapped << includeGuard.endifLine;
  if (!includeGuard.endifLine.empty() && includeGuard.endifLine.back() != '\n') {
    wrapped << '\n';
  }

  return wrapped.str();
}

absl::Status run(int argc, char** argv) {
  ABSL_ASSIGN_OR_RETURN(ModuleRequest request, parseModuleRequest(argc, argv));

  ComPtr<IGlobalSession> globalSession;
  ABSL_RETURN_IF_ERROR(checkSlangResult(
      "createGlobalSession",
      createGlobalSession(globalSession.writeRef())));

  auto commonOptions = makeCommonOptions();

  std::vector<CompilerOptionEntry> targetOptions = commonOptions;
  TargetDesc targetDesc;
  configureTargetDesc(globalSession.get(), targetOptions, targetDesc);

  std::vector<CompilerOptionEntry> sessionOptions = commonOptions;
  SessionDesc sessionDesc;
  std::array<const char*, 1> searchPaths{};
  configureSessionDesc(targetDesc, request, sessionOptions, searchPaths, sessionDesc);

  ComPtr<ISession> session;
  ABSL_RETURN_IF_ERROR(checkSlangResult(
      "IGlobalSession::createSession",
      globalSession->createSession(sessionDesc, session.writeRef())));

  ABSL_ASSIGN_OR_RETURN(ComPtr<IModule> libraryModule,
      loadSlangModule(session.get(), request.moduleName));

  ABSL_ASSIGN_OR_RETURN(std::vector<FunctionInfo> functions,
      collectEntryPoints(libraryModule.get(), request.moduleName));

  ABSL_ASSIGN_OR_RETURN(ComPtr<ICompileRequest> compileRequest,
      createCompileRequest(session.get(), request, targetDesc, functions));

  ABSL_ASSIGN_OR_RETURN(std::string hlslSource,
      collectGeneratedHlsl(compileRequest.get(), request.moduleName));

  fs::path rawOutputPath = request.outputPath;
  rawOutputPath.replace_extension(".raw.hlsl");
  ABSL_RETURN_IF_ERROR(writeTextFile(rawOutputPath, hlslSource));

  IncludeGuardInfo includeGuard = detectIncludeGuard(request.modulePath);
  std::string finalHlsl = applyIncludeGuard(hlslSource, includeGuard);
  ABSL_RETURN_IF_ERROR(writeTextFile(request.outputPath, finalHlsl));

  std::cerr << "Generated HLSL written to " << request.outputPath << std::endl;
  return absl::OkStatus();
}

int main(int argc, char** argv) {
  absl::Status status = run(argc, argv);
  if (!status.ok()) {
    std::cerr << status.message() << std::endl;
    return 1;
  }

  return 0;
}
