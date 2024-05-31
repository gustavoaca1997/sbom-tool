// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Sbom.Targets.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Sbom.Api.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;

/// <summary>
/// Class to test the generation of SBOM using SPDX 2.2 specification.
/// </summary>
[TestClass]
public class GenerateSbomTaskSPDX_2_2Tests : AbstractGenerateSbomTaskTests
{
    public GenerateSbomTaskSPDX_2_2Tests()
    {
        this.SbomSpecification = Constants.SPDX22Specification;
    }
}
