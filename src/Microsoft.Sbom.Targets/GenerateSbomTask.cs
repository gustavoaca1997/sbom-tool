// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Targets;

using System;
using System.Diagnostics.Tracing;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Sbom.Api;
using Microsoft.Sbom.Contracts;
using Microsoft.Sbom.Extensions.DependencyInjection;
using Microsoft.Sbom.Tool;
using Microsoft.VisualBasic;
using PowerArgs;
using Serilog.Events;

public class GenerateSbomTask : Task
{
    // TODO it is possible we will want to expose additional arguments, either as required or optional.
    // Will need to get SDK team/ windows team input on which arguments are necessary.

    /// <summary>
    /// The path to the drop directory for which the SBOM will be generated
    /// </summary>
    [Required]
    public string BuildDropPath { get; set; }

    /// <summary>
    /// The path to the directory containing build components and package information.
    /// For example, path to a .csproj or packages.config file.
    /// </summary>
    [Required]
    public string BuildComponentPath { get; set; }

    /// <summary>
    /// Supplier of the package the SBOM represents.
    /// </summary>
    [Required]
    public string PackageSupplier { get; set; }

    /// <summary>
    /// Name of the package the SBOM represents.
    /// </summary>
    [Required]
    public string PackageName { get; set; }

    /// <summary>
    /// Version of the package the SBOM represents.
    /// </summary>
    [Required]
    public string PackageVersion { get; set; }

    /// <summary>
    /// The base path of the SBOM namespace uri.
    /// </summary>
    [Required]
    public string NamespaceBaseUri { get; set; }

    /// <summary>
    /// A unique URI part that will be appended to NamespaceBaseUri.
    /// </summary>
    public string NamespaceUriUniquePart { get; set; }

    /// <summary>
    /// The path to a file containing a list of external SBOMs that will be appended to the
    /// SBOM that is being generated.
    /// </summary>
    public string ExternalDocumentListFile { get; set; }

    /// <summary>
    /// If true, it will fetch licensing information for detected packages.
    /// </summary>
    public bool FetchLicenseInformation { get; set; }

    /// <summary>
    /// If true, it will parse licensing and supplier information from a packages metadata file.
    /// </summary>
    public bool EnablePackageMetadataParsing { get; set; }

    /// <summary>
    /// Determines how detailed the outputed logging will be.
    /// </summary>
    public string Verbosity { get; set; }

    /// <summary>
    /// SBOM API utilizes EventLevel to determine
    /// verbosity level.
    /// </summary>
    public EventLevel EventLevelVerbosity { get; set; }

    /// <summary>
    /// A list of the name and version of the manifest format being used.
    /// </summary>
    public string ManifestInfo { get; set; }

    /// <summary>
    /// If true, it will delete the previously generated SBOM manifest directory before
    /// generating a new SBOM in ManifestDirPath.
    /// </summary>
    public bool DeleteManifestDirIfPresent { get; set; }

    /// <summary>
    /// The path where the SBOM will be generated.
    /// </summary>
    public string ManifestDirPath { get; set; }

    [Output]
    public string SbomPath { get; set; }

    public override bool Execute()
    {
        // Parse and assign verbosity accordingly
        this.ValidateAndAssignVerbosity();

        // Set other configurations. The GenerateSBOMAsyn() already sanitizes and checks for
        // a valid namespace URI and generates a random guid for NamespaceUriUniquePart if
        // one is not provided.
        var runtimeConfiguration = new RuntimeConfiguration()
        {
            DeleteManifestDirectoryIfPresent = this.DeleteManifestDirIfPresent,
            Verbosity = this.EventLevelVerbosity,
            NamespaceUriBase = this.NamespaceBaseUri,
            NamespaceUriUniquePart = this.NamespaceUriUniquePart
        };

        var metadata = new SBOMMetadata()
        {
            PackageName = this.PackageName,
            PackageVersion = this.PackageVersion,
            PackageSupplier = this.PackageSupplier
        };

        // TODO: figure out how to call GenerateSBOMAsync()

        try
        {
            // TODO replace this with a call to SBOM API to generate SBOM
            SbomPath = "path/to/sbom";
            return true;
        }
        catch (Exception e)
        {
            Log.LogError($"SBOM generation failed: {e.Message}");
            return false;
        }
    }

    /// <summary>
    /// Checks the user's input for Verbosity and assigns the
    /// associated EventLevel value for logging.
    /// </summary>
    private void ValidateAndAssignVerbosity()
    {
        if (string.IsNullOrEmpty(this.Verbosity))
        {
            Log.LogMessage("No verbosity level specified. Setting verbosity level at \"LogAlways\"");
            this.EventLevelVerbosity = EventLevel.LogAlways;
            return;
        }

        switch (this.Verbosity.ToUpper())
        {
            case "CRITICAL":
                this.EventLevelVerbosity = EventLevel.Critical;
                break;
            case "INFORMATIONAL":
                this.EventLevelVerbosity = EventLevel.Informational;
                break;
            case "ERROR":
                this.EventLevelVerbosity = EventLevel.Error;
                break;
            case "LOGALWAYS":
                this.EventLevelVerbosity = EventLevel.LogAlways;
                break;
            case "WARNING":
                this.EventLevelVerbosity = EventLevel.Warning;
                break;
            case "VERBOSE":
                this.EventLevelVerbosity = EventLevel.Verbose;
                break;
            default:
                Log.LogMessage("Unrecognized verbosity level specified. Setting verbosity level at \"LogAlways\"");
                this.EventLevelVerbosity = EventLevel.LogAlways;
                break;
        }
    }
}
