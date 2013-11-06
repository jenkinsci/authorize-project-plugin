Authorize Project plugin
========================

Jenkins plugin to configure a project to run with specified authorization

What's this?
------------

Authorize Project is a [Jenkins](http://jenkins-ci.org/) plugin.
This plugin provides following features (ones now planned):

* You can configure projects to have their builds run with specified authorization.
    * This is an implementation for [`QueueItemAuthenticator`](http://javadoc.jenkins-ci.org/jenkins/security/QueueItemAuthenticator.html).
* Provides following ways to specify authorization.
    * Run as the user who triggered the build.
        * Does not work for scheduled, or polled builds.
    * Run as the specified user.
        * You are requested to enter the password for the specified user when saving the project configuration.
        * In following cases, you can skip the password:
            * You are an administrator.
            * You are the specified user.
            * The specified user is not changed from the last configuration, and the project was configured "No need to re-enter passwords for the same authorization".
                * This can threaten your Jenkins security. Be careful to use.
* Provides an extension point to add new ways to specify authorization.

How to implement
----------------

* Requiring passwords can be done by following [scm-sync-configuration-plugin](https://wiki.jenkins-ci.org/display/JENKINS/SCM+Sync+configuration+plugin).
    * This base mechanism should be divided into another plugin.
