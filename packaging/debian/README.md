# Debian package building scripts
- `changelog` - Tracks changes between revisions. Package version is defined by latest entry.
- `control` - Defines package metadata and dependencies.
- `copyright` - Identifies the license for the package/source. 
    - Specifically delineates between the main code (Apache) and packaging (GPLv2).
- `postinst` - Runs *after* the deb package installs to perform additional configuration.
    - Creates `/var/lib/waagent` folder if not present.
- `postrm` - Runs *after* deb package removal to perform additional configuration.
    - Removes `/var/lib/waagent` folder if still present.
- `rules` - Make-compatible script for building deb package.