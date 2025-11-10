#  SPDX-FileCopyrightText: 2025 Tim Case
#
#  SPDX-License-Identifier: Apache-2.0
import argparse
from datetime import datetime
from typing import List
import argparse
import hashlib
import logging
import os
import pathlib
import subprocess

"""
HEAVILY Pulls from the upstream example https://github.com/spdx/tools-python/blob/ca72624a269247aadc235262a6030098b931f105/examples/spdx2_document_from_scratch.py
"""

from spdx_tools.spdx.model import (
    Actor,
    ActorType,
    Checksum,
    ChecksumAlgorithm,
    CreationInfo,
    Document,
    Package,
    Relationship,
    RelationshipType,
)
from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document
from spdx_tools.spdx.validation.validation_message import ValidationMessage
from spdx_tools.spdx.writer.write_anything import write_file

parser = argparse.ArgumentParser(
                    prog='RPMs2SBOM',
                    description='Generates an SBOM from a dir of RPMs',
                    formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument('dir', help="Root directory to walk for RPMs")
parser.add_argument('--out', default="sbom.json", help="JSON file to write SBOM to")
args = parser.parse_args()

creation_info = CreationInfo(
    spdx_version="SPDX-2.3",
    spdx_id="SPDXRef-DOCUMENT",
    name="RPM SBOM Manifest",
    data_license="CC0-1.0",
    document_namespace="https://rpm.sbom.example.com",
    creators=[Actor(ActorType.TOOL, "RPM SBOM Generator")],
    created=datetime.now(),
)

document = Document(creation_info)

pkgs_paths = []
for root, dirs, files in pathlib.Path(args.dir).walk(on_error=print):
    # Now we must locate all of the RPM packages here and generate Package objects for them
    for child in files:
        if child.endswith('.rpm'):
            pkgs_paths.append(pathlib.Path(f'{root}/{child}'))

# Going to shell out to rpm like a scrub and extract the package details for each package
query_format = "%{DESCRIPTION}||%{SUMMARY}||%{URL}||%{VERSION}||%{NAME}||%{BUILDTIME}||%{BUILDHOST}"
for p in pkgs_paths:
    _,out = subprocess.getstatusoutput(f'rpm -qp --queryformat "{query_format}" {p}')
    description, summary, url, version, pname, buildtime, buildhost = out.replace('\n', ' ').split('||')
    with open(p, 'rb') as fp:
        cs_sha1 = hashlib.file_digest(fp, 'sha1')
    pkg = Package(
        name=pname,
        spdx_id=f"SPDXRef-Package-{pname}",
        version=version,
        # To simplify validation when the signing-side of the operation has
        # downloaded all the target RPMs we only use the file name instead of
        # the relative or absolute path
        file_name=p.name,
        summary=summary,
        description=description,
        homepage=url,
        # Using buildhost in internal environments to know where to trace these back to
        download_location=buildhost,
        built_date=datetime.fromtimestamp(int(buildtime)),
        supplier=Actor(ActorType.PERSON, os.getlogin()),
        checksums=[
            Checksum(ChecksumAlgorithm.SHA1, cs_sha1.hexdigest()),
        ]
    )
    document.packages.append(pkg)

    # A DESCRIBES relationship asserts that the document indeed describes the package.
    # This works for as long as your package names only use valid chars
    document.relationships.append(Relationship("SPDXRef-DOCUMENT", RelationshipType.DESCRIBES, f"SPDXRef-Package-{pname}"))

# This library provides comprehensive validation against the SPDX specification.
# Note that details of the validation depend on the SPDX version of the document.
validation_messages: List[ValidationMessage] = validate_full_spdx_document(document)

# You can have a look at each entry's message and context (like spdx_id, parent_id, full_element)
# which will help you pinpoint the location of the invalidity.
for message in validation_messages:
    logging.warning(message.validation_message)
    logging.warning(message.context)

# If the document is valid, validation_messages will be empty.
assert validation_messages == []

# Finally, we can serialize the document to any of the five supported formats.
# Using the write_file() method from the write_anything module,
# the format will be determined by the file ending: .spdx (tag-value), .json, .xml, .yaml. or .rdf (or .rdf.xml)
write_file(document, args.out)
print(f"Wrote sbom: {args.out}")
