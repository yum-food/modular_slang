using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using UnityEditor;
using UnityEngine;

namespace ModularSlang.Editor
{
    internal sealed class ScriptLocator : ScriptableObject
    {
    }

    internal static class ModularSlangTranslator
    {
        private const string MenuPath = "Assets/Translate to HLSL";

        private static string s_cachedExecutablePath;
        private static bool s_missingExecutableLogged;

        [MenuItem(MenuPath, false, priority: 2000)]
        private static void TranslateSelectedSlang()
        {
            var slangAssets = GetSelectedSlangAssets()
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            TranslateSlangAssets(slangAssets, interactive: true, importOutputs: false);
        }

        [MenuItem(MenuPath, true)]
        private static bool TranslateSelectedSlangValidation()
        {
            return GetSelectedSlangAssets().Any();
        }

        private static IEnumerable<string> GetSelectedSlangAssets()
        {
            foreach (var obj in Selection.objects)
            {
                if (!obj)
                {
                    continue;
                }

                var assetPath = AssetDatabase.GetAssetPath(obj);
                if (string.IsNullOrEmpty(assetPath))
                {
                    continue;
                }

                if (assetPath.EndsWith(".slang", StringComparison.OrdinalIgnoreCase))
                {
                    yield return assetPath;
                }
            }
        }

        internal static void TranslateSlangAssets(IReadOnlyCollection<string> assetPaths, bool interactive, bool importOutputs)
        {
            if (assetPaths == null)
            {
                return;
            }

            var uniqueAssets = assetPaths
                .Where(path => !string.IsNullOrWhiteSpace(path))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (uniqueAssets.Count == 0)
            {
                return;
            }

            if (!TryGetExecutablePath(out var exePath, interactive))
            {
                return;
            }

            var projectRoot = Path.GetFullPath(Path.Combine(Application.dataPath, ".."));
            var showProgress = interactive && uniqueAssets.Count > 1;

            try
            {
                for (var i = 0; i < uniqueAssets.Count; ++i)
                {
                    var assetPath = uniqueAssets[i];
                    if (showProgress)
                    {
                        var progress = (i + 1f) / uniqueAssets.Count;
                        EditorUtility.DisplayProgressBar("Translating Slang", assetPath, progress);
                    }

                    RunTranslator(exePath, assetPath, projectRoot, importOutputs);
                }
            }
            finally
            {
                if (showProgress)
                {
                    EditorUtility.ClearProgressBar();
                }
            }

            if (interactive)
            {
                AssetDatabase.Refresh();
            }
        }

        private static bool TryGetExecutablePath(out string exePath, bool interactive)
        {
            exePath = GetExecutablePath();
            if (File.Exists(exePath))
            {
                s_missingExecutableLogged = false;
                return true;
            }

            var message =
                $"Could not locate modular_slang.exe next to the Scripts folder.\n\nExpected at:\n{exePath}";

            if (interactive)
            {
                EditorUtility.DisplayDialog("Modular Slang", message, "OK");
            }
            else if (!s_missingExecutableLogged)
            {
                UnityEngine.Debug.LogError(message);
                s_missingExecutableLogged = true;
            }

            return false;
        }

        private static string GetExecutablePath()
        {
            if (!string.IsNullOrEmpty(s_cachedExecutablePath))
            {
                return s_cachedExecutablePath;
            }

            var marker = ScriptableObject.CreateInstance<ScriptLocator>();
            try
            {
                var markerScript = MonoScript.FromScriptableObject(marker);
                var assetPath = AssetDatabase.GetAssetPath(markerScript);
                var projectRoot = Path.GetFullPath(Path.Combine(Application.dataPath, ".."));
                var scriptFullPath = Path.GetFullPath(Path.Combine(projectRoot, assetPath));

                var scriptDir = Path.GetDirectoryName(scriptFullPath) ?? string.Empty; // .../Scripts/Editor
                var scriptsDir = Path.GetDirectoryName(scriptDir) ?? string.Empty;      // .../Scripts
                var packageRoot = Path.GetDirectoryName(scriptsDir) ?? string.Empty;   // package root

                s_cachedExecutablePath = Path.Combine(packageRoot, "modular_slang.exe");
                return s_cachedExecutablePath;
            }
            finally
            {
                ScriptableObject.DestroyImmediate(marker);
            }
        }

        private static void RunTranslator(string exePath, string assetPath, string projectRoot, bool importOutput)
        {
            var inputFullPath = Path.GetFullPath(Path.Combine(projectRoot, assetPath));
            var outputFullPath = Path.ChangeExtension(inputFullPath, ".hlsl");
            var outputAssetPath = ToProjectRelativePath(outputFullPath, projectRoot);

            var startInfo = new ProcessStartInfo
            {
                FileName = exePath,
                Arguments = QuoteIfNeeded(inputFullPath),
                WorkingDirectory = Path.GetDirectoryName(exePath) ?? projectRoot,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };

            using (var process = Process.Start(startInfo))
            {
                if (process == null)
                {
                    UnityEngine.Debug.LogError("Failed to launch modular_slang.exe");
                    return;
                }

                var stdOut = process.StandardOutput.ReadToEnd();
                var stdErr = process.StandardError.ReadToEnd();
                process.WaitForExit();

                if (!string.IsNullOrWhiteSpace(stdOut))
                {
                    UnityEngine.Debug.Log(stdOut);
                }

                if (process.ExitCode != 0)
                {
                    var message = string.IsNullOrWhiteSpace(stdErr)
                        ? $"modular_slang.exe failed with exit code {process.ExitCode}"
                        : stdErr;
                    UnityEngine.Debug.LogError(message);
                    return;
                }

                if (!File.Exists(outputFullPath))
                {
                    UnityEngine.Debug.LogWarning($"Compilation succeeded but {outputFullPath} was not created.");
                }
                else
                {
                    UnityEngine.Debug.Log($"Generated {outputFullPath}");
                    if (importOutput && !string.IsNullOrEmpty(outputAssetPath))
                    {
                        AssetDatabase.ImportAsset(outputAssetPath, ImportAssetOptions.ForceUpdate);
                    }
                }
            }
        }

        private static string QuoteIfNeeded(string path)
        {
            return path.Contains(' ') ? $"\"{path}\"" : path;
        }

        private static string ToProjectRelativePath(string fullPath, string projectRoot)
        {
            if (string.IsNullOrEmpty(fullPath) || string.IsNullOrEmpty(projectRoot))
            {
                return string.Empty;
            }

            if (!fullPath.StartsWith(projectRoot, StringComparison.OrdinalIgnoreCase))
            {
                return string.Empty;
            }

            var relative = fullPath.Substring(projectRoot.Length)
                .TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            return relative.Replace(Path.DirectorySeparatorChar, '/');
        }
    }

    internal sealed class SlangAssetPostprocessor : AssetPostprocessor
    {
        private static readonly HashSet<string> s_pendingAssets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private static bool s_processingScheduled;

        private static void OnPostprocessAllAssets(
            string[] importedAssets,
            string[] deletedAssets,
            string[] movedAssets,
            string[] movedFromAssetPaths)
        {
            var added = false;

            foreach (var asset in importedAssets)
            {
                if (asset.EndsWith(".slang", StringComparison.OrdinalIgnoreCase))
                {
                    if (s_pendingAssets.Add(asset))
                    {
                        added = true;
                    }
                }
            }

            if (added && !s_processingScheduled)
            {
                s_processingScheduled = true;
                EditorApplication.delayCall += ProcessPending;
            }
        }

        private static void ProcessPending()
        {
            s_processingScheduled = false;

            if (s_pendingAssets.Count == 0)
            {
                return;
            }

            var assets = s_pendingAssets.ToArray();
            s_pendingAssets.Clear();

            ModularSlangTranslator.TranslateSlangAssets(assets, interactive: false, importOutputs: true);
        }
    }
}
