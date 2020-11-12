# authorize-project-plugin Changelog

## Version 1.3.0 (Feb 12, 2017)

* Split the configuration of authentication into a separate screen
([JENKINS-35081](https://issues.jenkins-ci.org/browse/JENKINS-35081))
  * See [Screenshots](https://wiki.jenkins.io/display/JENKINS/Authorize+Project+plugin#AuthorizeProjectplugin-Screenshots)
  for details.

## Version 1.2.2 (May 28, 2016)

* Fixed: Builds aren't start when security realm fail to find the user
for authorization (e.g. Bind DN is not set for Active Directory
plugin)
([JENKINS-34279](https://issues.jenkins-ci.org/browse/JENKINS-34279))

## Version 1.2.1 (Apr 03, 2016)

* Fixed: password / api token fields for "Run as Specific User" are
broken ([JENKINS-33897](https://issues.jenkins-ci.org/browse/JENKINS-33897))

## Version 1.2.0 (Mar 27, 2016)

* *Targets Jenkins 1.625*
* SECURITY FIX: Reject unauthenticated configurations via REST / CLI
([JENKINS-28298](https://issues.jenkins-ci.org/browse/JENKINS-28298))
  * See [JENKINS-28298](https://wiki.jenkins.io/display/JENKINS/JENKINS-28298) for details.
* Support global default authorization strategy
([JENKINS-30574](https://issues.jenkins-ci.org/browse/JENKINS-30574))
* Displays an error when a built-in user is used for "Run as Specific
User"
([JENKINS-32769](https://issues.jenkins-ci.org/browse/JENKINS-32769))
* Added "Run as SYSTEM"
([JENKINS-32770](https://issues.jenkins-ci.org/browse/JENKINS-32770))
  * Disabled by default for projects. You have to enable it in the
  global security configuration page.

## Version 1.1.0 (Aug 9, 2015)

* Added a feature to enable / disable strategies.
([JENKINS-28298](https://issues.jenkins-ci.org/browse/JENKINS-28298))
  * *"Run as Specific User" is disabled by default. You need to   enable it after upgrading from a prior version if you use it.*
* Supports workflow ([JENKINS-26670](https://issues.jenkins-ci.org/browse/JENKINS-26670))
* Supports apitoken for authentication. ([JENKINS-22470](https://issues.jenkins-ci.org/browse/JENKINS-22470))
* Add support for upcoming $class annotation change ([JENKINS-25403](https://issues.jenkins-ci.org/browse/JENKINS-25403))

## Version 1.0.3 (Apr 14, 2014)

* *SECURITY FIX*: Authentication of "Run as Specific User" is easily
bypassed by REST/CLI added (Fixed [JENKINS-22469](https://issues.jenkins-ci.org/browse/JENKINS-22469))
* Replaced radio buttons to dropdown selecting authorization
strategies (Fixed [JENKINS-20786](https://issues.jenkins-ci.org/browse/JENKINS-20786))

## Version 1.0.2 (Feb 22, 2014)

* added `AuthorizeProjectStrategyDescriptor` ([JENKINS-20812](https://issues.jenkins-ci.org/browse/JENKINS-20812))
* Not to send the password value to test whether password is required.

## Version 1.0.1 (Nov 30, 2013)

* Fix a problem that a new user created if you authenticate with
non-existent user (Fix [JENKINS-20784](https://issues.jenkins-ci.org/browse/JENKINS-20784))
* Works with MatrixProject (Fix [JENKINS-20785](https://issues.jenkins-ci.org/browse/JENKINS-20785))

## Version 1.0.0 (Nov 24, 2013)

* Initial release.
