// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
namespace Microsoft.Sbom.Targets;

using System;
using Microsoft.Build.Framework;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Sbom.Api;
using Microsoft.Sbom.Extensions.DependencyInjection;
using Microsoft.Sbom.Tool;
using PowerArgs;
using Task = Microsoft.Build.Utilities.Task;

public class GenerateSbomTask : Task
{
    // TODO it is possible we will want to expose additional arguments, either as required or optional.
    // Will need to get SDK team/ windows team input on which arguments are necessary.
    [Required]
    public string BuildDropPath { get; set; }

    [Required]
    public string BuildComponentPath { get; set; }

    [Required]
    public string PackageSupplier { get; set; }

    [Required]
    public string PackageName { get; set; }

    [Required]
    public string PackageVersion { get; set; }

    [Output]
    public string SbomPath { get; set; }

    public override bool Execute()
    {
        if (string.IsNullOrEmpty(this.BuildDropPath) ||
            string.IsNullOrEmpty(this.BuildComponentPath) ||
            string.IsNullOrEmpty(this.PackageSupplier) ||
            string.IsNullOrEmpty(this.PackageName) ||
            string.IsNullOrEmpty(this.PackageVersion))
        {
            this.Log.LogError("Required argument not provided.");
            return false;
        }

        try
        {
            // TODO replace this with a call to SBOM API to generate SBOM 
            this.SbomPath = "path/to/sbom";
            return true;
        }
        catch (Exception e)
        {
            this.Log.LogError($"SBOM generation failed: {e.Message}");
            return false;
        }
    }
}
