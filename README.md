# Snyk Auto-Jira

This project contains a Forge app written in Javascript that automatically opens Jira issues for issues discovered during Snyk scans.

Users may configure the application on a per-project basis in their Jira environment.

See [developer.atlassian.com/platform/forge/](https://developer.atlassian.com/platform/forge) for documentation and tutorials explaining Forge.

## Usage Requirements

- You'll need a Jira cloud environment and permissions to install.
- Configure the app from a project settings page in Jira.
- Use the app-provided callback to set up a Snyk webhook.

## Development

### System Requirements

- NodeJS (LTS) 
- @forge/cli 
- Docker (optional)

Installing `@forge/cli` globally is recommended.

/If you are using the excellent `asdf` project for NodeJS version management,
the `.tool-versions` file at the root of the repository should ensure your setup
is correct with minimal effort./

### Prerequisites

- Access to an Atlassian Cloud developer site
- An Atlassian API token

Detailed information about the items in the list above can be found in the 
[Forge developer documentation](https://developer.atlassian.com/platform/forge/getting-started/).

Before you can work with a Forge app in any meaningful way, you'll need to
configure the Forge CLI tool. The short version of this process is to simply
run:

``` shell
forge login
```

For further information, again refer to the Forge developer documentation linked
above.

### Installing and Running

1. Firstly, the project must be **deployed** to an environment. The
   separation/concept of /environments/ within the context of Atlassian Cloud and
   Jira can be somewhat confusing, but for now it is enough to know that there are
   typically three environments of interest: `development`, `staging`, and
   `production`.

    The application is deployed to development, by default, via:

    ``` shell
    $ forge deploy
    ```

    To deploy to other environments, pass the `-e` argument with the environment.



2. Once deployed, the application must be installed. This can be accomplished
   via the administration interface within your Jira project, or via the CLI
   directly.
   
   ```shell
   $ forge install 
   ```

3. (Optional) Once installed, you can forward requests to the application to
   your local machine which is very useful for debugging. Doing so also enables
   hot-reloading of the application, allowing you to make changes without
   needing to constantly redeploy. 
   
   This functionality requires Docker.
   
   ```shell
   $ forge tunnel
   ```

4. At this point, you should head over to the application's settings page within Jira.
   To do so, find the **Project settings** link in Jira's sidebar, expand the
   **Apps** tree, then select **Snyk Auto-Issues for Jira**.

5. When the settings have been configured you're ready to develop.

### Handy Helpers

If there are major changes you may be required to run the following command after deploying:

``` shell
$ forge install --upgrade
```

You can print information about where the application is installed:

``` shell
$ forge install list
```

Since this application relies on a webhook, you can generate a callback URL for development using:

``` shell
$ forge webtrigger
```

Normally to view the application's logs you'd need to visit the [Atlassian cloud
developer console](https://developer.atlassian.com/console/myapps/), which isn't
great if you're looking for something specific.

When working in the _development_ environment with `forge tunnel`, the logs are
streamed live to STDOUT, but for other environments, the best option is `forge
logs`. With no arguments, the data returned can be difficult to parse and mostly
appears to have no logical order. 

You can view logs grouped by invocation and filtered by environment from the
last hour by :

``` shell
$ forge logs -e production -g -s 1h
```

`
