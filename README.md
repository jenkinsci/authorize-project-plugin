Authorize Project plugin
========================

[Jenkins](https://jenkins.io) plugin to configure a project to run with specified authorization.

What's this?
------------

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

Extension point
---------------

A new way to authorize projects can be added by extending `org.jenkinsci.plugins.authorizeproject.AuthorizeProjectStrategy`, overriding the following method:

```
public abstract Authentication authenticate(hudson.model.AbstractProject<?, ?> project, hudson.model.Queue.Item item);
```
