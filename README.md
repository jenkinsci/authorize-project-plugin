# Authorize Project Plugin

## What's this

This plugin provides following features:

* Projects can be configured to have their builds run with specified authorization.
  * This is an implementation for [`QueueItemAuthenticator`](https://javadoc.jenkins-ci.org/jenkins/security/QueueItemAuthenticator.html).
* The following ways are provided to specify authorization.
  * Run as the user who triggered the build.
    * Does not work for scheduled, or polled builds.
  * Run as anonymous.
  * Run as the specified user.
    * You are requested to enter the password of the specified user except for the following cases:
      * You are an administrator.
      * You are the specified user.
      * The specified user is not changed from the last configuration, and "No need for re-authentication" is checked.
        * This can threaten your Jenkins security. Be careful to use.
* Provides an extension point to add new ways to specify authorization.

## Extension point

A new way to authorize projects can be added by extending `org.jenkinsci.plugins.authorizeproject.AuthorizeProjectStrategy`, overriding the following method:

```java
public abstract Authentication authenticate(hudson.model.AbstractProject<?, ?> project, hudson.model.Queue.Item item);
```

## Screenshots

* After installed Authorize Project plugin, you will find "Access
  Control for Builds" in "Manage Jenkins" > "Configure Global
  Security". Adding "Configure Build Authorizations in Project
  Configuration" enables Authorize Project plugin.
  ![global security](docs/images/authorize-project_01_globalsecurity.png)
  * You can also disable specific strategies in this page. Disabled
    strategies are never used for authorization.
* A new side bar menu "Authorization" will appear in project pages.
  ![sidebar](docs/images/sidebar.png)
* You can select how to authorize builds of the project in the
  "Authorization" page. ![authorization page](docs/images/authorization-page.png)
* When selecting "Run as Specific User", you can enter User ID with
  whose authorization builds will run. If you enter a user ID except
  yourself and have no administrative privilege, you are required to
  enter the password of that user. ![authorization page specific user](docs/images/authorization-page-specific-user.png)
  * You can also use API token, especially for non password-based
    security realms.
* Configuring project settings by unauthorized users are forbidden
  when you configure the authorization for the project. See [What's
  this?](https://wiki.jenkins.io/display/JENKINS/Authorize+Project+plugin#AuthorizeProjectplugin-What%27sthis?)
  for details. ![access denied](docs/images/access-denied.png)

## Issues

To report a bug or request an enhancement to this plugin please create a
ticket in JIRA (you need to login or to sign up for an account). Also
have a look on [How to report an issue](https://wiki.jenkins.io/display/JENKINS/How+to+report+an+issue)

* [Bug report](https://issues.jenkins-ci.org/secure/CreateIssueDetails!init.jspa?pid=10172&issuetype=1&components=18155&priority=4&assignee=ikedam)
* [Request or propose an improvement of existing feature](https://issues.jenkins-ci.org/secure/CreateIssueDetails!init.jspa?pid=10172&issuetype=4&components=18155&priority=4)
* [Request or propose a new feature](https://issues.jenkins-ci.org/secure/CreateIssueDetails!init.jspa?pid=10172&issuetype=2&components=18155&priority=4)
