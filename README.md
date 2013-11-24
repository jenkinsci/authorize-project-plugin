Authorize Project plugin
========================

Jenkins plugin to configure a project to run with specified authorization

What's this?
------------

Authorize Project is a [Jenkins](http://jenkins-ci.org/) plugin.
This plugin provides following features:

* You can configure projects to have their builds run with specified authorization.
    * This is an implementation for [`QueueItemAuthenticator`](http://javadoc.jenkins-ci.org/jenkins/security/QueueItemAuthenticator.html).
* Provides following ways to specify authorization.
    * Run as the user who triggered the build.
        * Does not work for scheduled, or polled builds.
    * Run as anonymous.
    * Run as the specified user.
        * You are requested to enter the password of the specified user except following cases:
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

