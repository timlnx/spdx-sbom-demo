# RPMs2SBOM

Quick demo of using the `spdx-tools` python library to generate an SBOM from a
directory tree of RPMs.

* https://pypi.org/project/spdx-tools/
* https://github.com/spdx/tools-python/blob/ca72624a269247aadc235262a6030098b931f105/examples/spdx2_document_from_scratch.py

**Usage**

Imagine you have a directory of RPMs somewhere:

```
$ ls -l ../pkgs/
total 3480
-rw-r--r--. 1 tc tc  140606 Nov 10 01:34 figlet-2.2.5-28.20151018gita565ae1.fc40.x86_64.rpm
-rw-r--r--. 1 tc tc 3409873 Nov 10 03:41 zsh-5.9-14.fc40.x86_64.rpm
$ sha1sum ../pkgs/*.rpm
c10778672a98b375e5345cfef7b3e973e0c231cf  ../pkgs/figlet-2.2.5-28.20151018gita565ae1.fc40.x86_64.rpm
c86d3ef411bd71fc28a3c4ce79906033a8440a8b  ../pkgs/zsh-5.9-14.fc40.x86_64.rpm
```

You can run this script and provide the relative path to that directory. It will
generate an SBOM from those files.

```
usage: RPMs2SBOM [-h] [--out OUT] dir

Generates an SBOM from a dir of RPMs

positional arguments:
  dir         Root directory to walk for RPMs

options:
  -h, --help  show this help message and exit
  --out OUT   JSON file to write SBOM to (default: sbom.json)
```

Running with the only required argument:

```
$ python ./rpmsign-uploader.py ../pkgs/
Wrote sbom: sbom.json
```

Which we can examine like this:

```json
$ jq . < sbom.json
{
  "SPDXID": "SPDXRef-DOCUMENT",
  "creationInfo": {
    "created": "2025-11-10T04:17:49Z",
    "creators": [
      "Tool: RPM SBOM Generator"
    ]
  },
  "dataLicense": "CC0-1.0",
  "name": "RPM SBOM Manifest",
  "spdxVersion": "SPDX-2.3",
  "documentNamespace": "https://rpm.sbom.example.com",
  "packages": [
    {
      "SPDXID": "SPDXRef-Package-figlet",
      "builtDate": "2024-01-24T11:36:48Z",
      "checksums": [
        {
          "algorithm": "SHA1",
          "checksumValue": "c10778672a98b375e5345cfef7b3e973e0c231cf"
        }
      ],
      "description": "FIGlet prints its input using large characters (called \"FIGcharacters\") made up of ordinary screen characters (called \"sub-characters\"). FIGlet output is generally reminiscent of the sort of \"signatures\" many people like to put at the end of e-mail and UseNet messages. It is also reminiscent of the output of some banner programs, although it is oriented normally, not sideways.",
      "downloadLocation": "buildvm-x86-08.iad2.fedoraproject.org",
      "filesAnalyzed": true,
      "homepage": "http://www.figlet.org/",
      "name": "figlet",
      "packageFileName": "figlet-2.2.5-28.20151018gita565ae1.fc40.x86_64.rpm",
      "summary": "A program for making large letters out of ordinary text",
      "supplier": "Person: tc",
      "versionInfo": "2.2.5"
    },
    {
      "SPDXID": "SPDXRef-Package-zsh",
      "builtDate": "2024-05-13T10:27:21Z",
      "checksums": [
        {
          "algorithm": "SHA1",
          "checksumValue": "c86d3ef411bd71fc28a3c4ce79906033a8440a8b"
        }
      ],
      "description": "The zsh shell is a command interpreter usable as an interactive login shell and as a shell script command processor.  Zsh resembles the ksh shell (the Korn shell), but includes many enhancements.  Zsh supports command line editing, built-in spelling correction, programmable command completion, shell functions (with autoloading), a history mechanism, and more.",
      "downloadLocation": "buildhw-x86-15.iad2.fedoraproject.org",
      "filesAnalyzed": true,
      "homepage": "http://zsh.sourceforge.net/",
      "name": "zsh",
      "packageFileName": "zsh-5.9-14.fc40.x86_64.rpm",
      "summary": "Powerful interactive shell",
      "supplier": "Person: tc",
      "versionInfo": "5.9"
    }
  ],
  "relationships": [
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relatedSpdxElement": "SPDXRef-Package-figlet",
      "relationshipType": "DESCRIBES"
    },
    {
      "spdxElementId": "SPDXRef-DOCUMENT",
      "relatedSpdxElement": "SPDXRef-Package-zsh",
      "relationshipType": "DESCRIBES"
    }
  ]
}
```
