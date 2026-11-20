# Release notes

Each release has its notes here as `vX.Y.Z.md`, written for users and reviewed in the release pull request. The release workflow refuses a tag without them, and makes them the body of the GitHub release, followed by [verifying.md](verifying.md), the section on checking the downloads that every release shares. `{{TAG}}` in it becomes the tag, so its links keep pointing at that release.

Earlier releases follow this outline, with only the sections that apply:

- One or two sentences on what the release is about, and whether commands, output, exit codes and file formats changed.
- **New** and **Behaviour changes**: anything a user or script could notice.
- **Security fixes**, in pqsign or its dependencies, with advisory IDs, and whether pqsign was affected.
- **Under the hood** and **Documentation**: smaller changes worth knowing, including changes to the library API.

Links into the repository point at the tag, as in `blob/vX.Y.Z/docs/install.md`, so they keep working.
