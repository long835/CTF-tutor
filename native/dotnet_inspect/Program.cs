// dotnet-inspect: reads .NET assembly metadata (types, methods, referenced
// assemblies, entry point) from a compiled .NET binary and prints it as
// JSON.
//
// Why C#, specifically: this reads the CLI metadata format directly using
// System.Reflection.Metadata / System.Reflection.PortableExecutable --
// both part of the .NET base class library, so no external decompiler
// (ILSpy, dnSpy, etc.) needs to be installed separately. This is the
// first-party way to read this format; a pure-Python alternative exists
// (the third-party `dnfile` package parses the same structures), but it
// re-implements what .NET's own BCL already does natively, and using the
// BCL directly leaves room to add real decompilation later via
// ICSharpCode.Decompiler (also C#) without a second metadata parser.
//
// This targets a CTF-tutor gap noted earlier: static_analysis.py has no
// dedicated evidence-gathering for .NET/C# `rev` challenges, which are a
// common category alongside native ELF/PE reversing.
//
// NOTE: there is no .NET SDK in the environment this was written in, so
// this could not be compiled or run here. The System.Reflection.Metadata
// API surface used below (PEReader, MetadataReader, TypeDefinition,
// MethodDefinition, AssemblyReference) is written from the documented
// API; verify with `dotnet build` before wiring it into the pipeline,
// the same caution that applies to any new tool wrapper in this repo.
//
// Usage:
//   dotnet run --project native/dotnet_inspect -- <path-to-dll-or-exe>

using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Text.Json;

if (args.Length < 1)
{
    Console.Error.WriteLine("usage: dotnet-inspect <path-to-dll-or-exe>");
    return 1;
}

string path = args[0];
if (!File.Exists(path))
{
    Console.Error.WriteLine($"error: file not found: {path}");
    return 1;
}

try
{
    using FileStream stream = File.OpenRead(path);
    using PEReader peReader = new(stream);

    if (!peReader.HasMetadata)
    {
        Console.Error.WriteLine("error: not a .NET assembly (no CLI metadata found)");
        return 1;
    }

    MetadataReader md = peReader.GetMetadataReader();

    string? assemblyName = null;
    if (md.IsAssembly)
    {
        AssemblyDefinition asmDef = md.GetAssemblyDefinition();
        assemblyName = md.GetString(asmDef.Name);
    }

    var referencedAssemblies = new List<string>();
    foreach (AssemblyReferenceHandle handle in md.AssemblyReferences)
    {
        AssemblyReference asmRef = md.GetAssemblyReference(handle);
        referencedAssemblies.Add(md.GetString(asmRef.Name));
    }

    var types = new List<object>();
    foreach (TypeDefinitionHandle handle in md.TypeDefinitions)
    {
        TypeDefinition typeDef = md.GetTypeDefinition(handle);
        string typeName = md.GetString(typeDef.Name);

        // Skip compiler-generated / module-level placeholder types --
        // not useful evidence for a learner and just adds noise.
        if (typeName.StartsWith('<') || typeName == "<Module>")
        {
            continue;
        }

        var methods = new List<string>();
        foreach (MethodDefinitionHandle methodHandle in typeDef.GetMethods())
        {
            MethodDefinition methodDef = md.GetMethodDefinition(methodHandle);
            methods.Add(md.GetString(methodDef.Name));
        }

        types.Add(new
        {
            name = typeName,
            @namespace = md.GetString(typeDef.Namespace),
            methods,
        });
    }

    bool isIlOnly = peReader.PEHeaders.CorHeader is { } corHeader
        && (corHeader.Flags & CorFlags.ILOnly) != 0;

    var result = new
    {
        assembly_name = assemblyName,
        is_il_only = isIlOnly,
        entry_point_token = peReader.PEHeaders.CorHeader?.EntryPointTokenOrRelativeVirtualAddress,
        referenced_assemblies = referencedAssemblies,
        type_count = types.Count,
        types,
    };

    Console.WriteLine(JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }));
    return 0;
}
catch (BadImageFormatException)
{
    Console.Error.WriteLine("error: not a valid PE/.NET image");
    return 1;
}
