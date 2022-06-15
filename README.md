# Snyk Auto-Jira

This project contains a Forge app written in Javascript that automatically opens Jira issues for issues discovered during Snyk scans.

Users may configure the application on a per-project basis in their Jira environment.

See [developer.atlassian.com/platform/forge/](https://developer.atlassian.com/platform/forge) for documentation and tutorials explaining Forge.

## Usage Requirements

- You'll need a Jira cloud environment and permissions to install.
- Configure the app from a project settings page in Jira.
- Use the app-provided callback to set up a Snyk webhook.
