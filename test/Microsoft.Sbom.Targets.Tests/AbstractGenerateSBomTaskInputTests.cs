// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using Microsoft.Build.Framework;
using Microsoft.Sbom.Contracts;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace Microsoft.Sbom.Targets.Tests;

[TestClass]
public abstract class AbstractGenerateSBomTaskInputTests
{
    internal abstract SbomSpecification SbomSpecification { get; }

    internal static readonly string CurrentDirectory = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location);
    internal static readonly string DefaultManifestDirectory = Path.Combine(CurrentDirectory, "_manifest");
    internal static readonly string TemporaryDirectory = Path.Combine(CurrentDirectory, "_temporary");
    internal static readonly string BuildComponentPath = Path.Combine(CurrentDirectory, "..", "..", "..");
    internal static readonly string ExternalDocumentListFile = Path.GetRandomFileName();
    internal const string PackageSupplier = "Test-Microsoft";
    internal const string PackageName = "CoseSignTool";
    internal const string PackageVersion = "0.0.1";
    internal const string NamespaceBaseUri = "https://base0.uri";

    private Mock<IBuildEngine> buildEngine;
    private List<BuildErrorEventArgs> errors;

    [TestInitialize]
    public void Startup()
    {
        // Setup the build engine
        this.buildEngine = new Mock<IBuildEngine>();
        this.errors = new List<BuildErrorEventArgs>();
        this.buildEngine.Setup(x => x.LogErrorEvent(It.IsAny<BuildErrorEventArgs>())).Callback<BuildErrorEventArgs>(e => errors.Add(e));
    }

    [TestCleanup]
    public void Cleanup() {
        // Clean up the manifest directory
        if (Directory.Exists(DefaultManifestDirectory))
        {
            Directory.Delete(DefaultManifestDirectory, true);
        }

        // Clean up the manifest directory
        if (Directory.Exists(TemporaryDirectory))
        {
            Directory.Delete(TemporaryDirectory, true);
        }
    }

    /// <summary>
    /// Test for ensuring the GenerateSbomTask fails for null or empty inputs for
    /// required params, which includes BuildDropPath, PackageSupplier, PackageName,
    /// PackageVersion, and NamespaceBaseUri.
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(GetNullRequiredParamsData), DynamicDataSourceType.Method)]
    [DynamicData(nameof(GetEmptyRequiredParamsData), DynamicDataSourceType.Method)]
    public void Sbom_Fails_With_Null_And_Empty_Required_Params(
        string buildDropPath,
        string packageSupplier,
        string packageName,
        string packageVersion,
        string namespaceBaseUri)
    {
        // Arrange.
        var task = new GenerateSbomTask
        {
            BuildDropPath = buildDropPath,
            PackageSupplier = packageSupplier,
            PackageName = packageName,
            PackageVersion = packageVersion,
            NamespaceBaseUri = namespaceBaseUri,
            ManifestInfo = this.SbomSpecification.ToString(),
            BuildEngine = this.buildEngine.Object
        };

        // Act
        var result = task.Execute();

        // Assert
        Assert.IsFalse(result);
    }

    private static IEnumerable<object[]> GetNullRequiredParamsData()
    {
        yield return new object[] { null, PackageSupplier, PackageName, PackageVersion, NamespaceBaseUri };
        yield return new object[] { CurrentDirectory, null, PackageName, PackageVersion, NamespaceBaseUri };
        yield return new object[] { CurrentDirectory, PackageSupplier, null, PackageVersion, NamespaceBaseUri };
        yield return new object[] { CurrentDirectory, PackageSupplier, PackageName, null, NamespaceBaseUri };
        yield return new object[] { CurrentDirectory, PackageSupplier, PackageName, PackageVersion, null };
    }

    private static IEnumerable<object[]> GetEmptyRequiredParamsData()
    {
        yield return new object[] { string.Empty, PackageSupplier, PackageName, PackageVersion, NamespaceBaseUri };
        yield return new object[] { CurrentDirectory, string.Empty, PackageName, PackageVersion, NamespaceBaseUri };
        yield return new object[] { CurrentDirectory, PackageSupplier, string.Empty, PackageVersion, NamespaceBaseUri };
        yield return new object[] { CurrentDirectory, PackageSupplier, PackageName, string.Empty, NamespaceBaseUri };
        yield return new object[] { CurrentDirectory, PackageSupplier, PackageName, PackageVersion, string.Empty };
    }

    /// <summary>
    /// Test for ensuring the GenerateSbomTask fails when user provides an
    /// invalid URI format.
    /// </summary>
    [TestMethod]
    public void Sbom_Fails_With_Invalid_NamespaceBaseUri()
    {
        // Arrange
        var task = new GenerateSbomTask
        {
            BuildDropPath = CurrentDirectory,
            PackageSupplier = PackageSupplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = "incorrectly_formatted_uri.com",
            ManifestInfo = this.SbomSpecification.ToString(),
            BuildEngine = this.buildEngine.Object
        };

        // Act
        var result = task.Execute();

        // Assert
        Assert.IsFalse(result);
    }

    /// <summary>
    /// Test for ensuring the GenerateSbomTask fails when user provides
    /// an invalid GUID for NamespaceUriUniquePart.
    /// </summary>
    [TestMethod]
    public void Sbom_Generation_Fails_For_Invalid_NamespaceUriUniquePart()
    {
        // Arrange
        var task = new GenerateSbomTask
        {
            BuildDropPath = CurrentDirectory,
            PackageSupplier = PackageSupplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = NamespaceBaseUri,
            NamespaceUriUniquePart = "-1",
            ManifestInfo = this.SbomSpecification.ToString(),
            BuildEngine = this.buildEngine.Object
        };

        // Act
        var result = task.Execute();

        // Assert
        Assert.IsFalse(result);
    }

    /// <summary>
    /// Test for ensuring the GenerateSbomTask fails when relative paths are
    /// provided for all path arguments, which includes BuildDroppath, BuildComponentPath,
    /// ManifestDirPath, and ExternalDocumentListFile
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(GetUnrootedPathTestData), DynamicDataSourceType.Method)]
    public void Sbom_Fails_With_Unrooted_Paths(
        string buildDropPath,
        string buildComponentPath,
        string manifestDirPath,
        string externalDocumentListFile)
    {
        // Arrange.
        var task = new GenerateSbomTask
        {
            BuildDropPath = buildDropPath,
            PackageSupplier = PackageSupplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = NamespaceBaseUri,
            BuildComponentPath = buildComponentPath,
            ManifestDirPath = manifestDirPath,
            ExternalDocumentListFile = externalDocumentListFile,
            ManifestInfo = this.SbomSpecification.ToString(),
            BuildEngine = this.buildEngine.Object
        };

        // Act
        var result = task.Execute();

        // Assert
        Assert.IsFalse(result);
    }

    private static IEnumerable<object[]> GetUnrootedPathTestData()
    {
        yield return new object[] { "../../", BuildComponentPath, DefaultManifestDirectory, ExternalDocumentListFile };
        yield return new object[] { CurrentDirectory, "../../", DefaultManifestDirectory, ExternalDocumentListFile };
        yield return new object[] { CurrentDirectory, BuildComponentPath, "../../", ExternalDocumentListFile };
        yield return new object[] { CurrentDirectory, BuildComponentPath, DefaultManifestDirectory, "../../" };
    }

    /// <summary>
    /// Test for ensuring GenerateSbomTask assigns a defualt Verbosity
    /// level when null input is provided.
    /// </summary>
    [TestMethod]
    public void Sbom_Generation_Succeeds_For_Null_Verbosity()
    {
        // Arrange
        // If Verbosity is null, the default value should be Verbose and is printed in the
        // tool's standard output.
        var pattern = new Regex("Verbosity=.*Value=Verbose");
        var stringWriter = new StringWriter();
        Console.SetOut(stringWriter);
        var task = new GenerateSbomTask
        {
            BuildDropPath = CurrentDirectory,
            PackageSupplier = PackageSupplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = NamespaceBaseUri,
            ManifestInfo = this.SbomSpecification.ToString(),
            Verbosity = null,
            BuildEngine = this.buildEngine.Object
        };

        // Act
        var result = task.Execute();
        var output = stringWriter.ToString();

        // Assert
        Assert.IsTrue(result);
        Assert.IsTrue(pattern.IsMatch(output));
    }

    /// <summary>
    /// Test for ensuring GenerateSbomTask assigns a default Verbosity for
    /// unrecognized input.
    /// </summary>
    [TestMethod]
    public void Sbom_Generation_Succeeds_For_Invalid_Verbosity()
    {
        // Arrange
        // If an invalid Verbosity is specified, the default value should be Verbose and is printed in the
        // tool's standard output.
        var pattern = new Regex("Verbosity=.*Value=Verbose");
        var stringWriter = new StringWriter();
        Console.SetOut(stringWriter);
        var task = new GenerateSbomTask
        {
            BuildDropPath = CurrentDirectory,
            PackageSupplier = PackageSupplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = NamespaceBaseUri,
            Verbosity = "Invalid Verbosity",
            ManifestInfo = this.SbomSpecification.ToString(),
            BuildEngine = this.buildEngine.Object
        };

        // Act
        var result = task.Execute();
        var output = stringWriter.ToString();

        // Assert
        Assert.IsTrue(result);
        Assert.IsTrue(pattern.IsMatch(output));
    }

    /// <summary>
    /// Test to ensure GenerateSbomTask correctly parses and provides each EventLevel verbosity
    /// values to the SBOM API.
    /// </summary>
    [TestMethod]
    [DataRow("CRITICAL", "Fatal")]
    [DataRow("informational", "Information")]
    [DataRow("LoGAlwAys", "Verbose")]
    [DataRow("Warning", "Warning")]
    [DataRow("eRRor", "Error")]
    [DataRow("verBOSE", "Verbose")]
    public void Sbom_Generation_Assigns_Correct_Verbosity_IgnoreCase(string inputVerbosity, string mappedVerbosity)
    {
        // Arrange
        var pattern = new Regex($"Verbosity=.*Value={mappedVerbosity}");
        var stringWriter = new StringWriter();
        Console.SetOut(stringWriter);
        var task = new GenerateSbomTask
        {
            BuildDropPath = CurrentDirectory,
            PackageSupplier = PackageSupplier,
            PackageName = PackageName,
            PackageVersion = PackageVersion,
            NamespaceBaseUri = NamespaceBaseUri,
            Verbosity = inputVerbosity,
            ManifestInfo = this.SbomSpecification.ToString(),
            BuildEngine = this.buildEngine.Object
        };

        // Act
        var result = task.Execute();
        var output = stringWriter.ToString();

        // Assert
        Assert.IsTrue(result);
        Assert.IsTrue(pattern.IsMatch(output));
    }
}
