# authorize-project-plugin Changelog

## [1.3.2] - 2020-11-19

### Added
* Add documentation from wiki to README and CHANGELOG.
* Add image files from wiki to documentation.

## [1.3.0] - 2017-02-12

### Changed
* [JENKINS-35081](https://issues.jenkins-ci.org/browse/JENKINS-35081): Split the configuration of 
authentication into a separate screen.
  * See [Screenshots](https://wiki.jenkins.io/display/JENKINS/Authorize+Project+plugin#AuthorizeProjectplugin-Screenshots)
  for details.

## [1.2.2] - 2016-05-28

### Fixed
* [JENKINS-34279](https://issues.jenkins-ci.org/browse/JENKINS-34279): Builds weren't start when security 
realm fail to find the user for authorization (e.g. Bind DN is not set for **Active Directory Plugin**).

## [1.2.1] - 2016-04-03

### Fixed
* [JENKINS-33897](https://issues.jenkins-ci.org/browse/JENKINS-3389): Password/API token fields for
**"Run as Specific User"** were broken.

## [1.2.0] - 2016-03-27

### Added
* "Run as SYSTEM". ([JENKINS-32770](https://issues.jenkins-ci.org/browse/JENKINS-32770))
  * Disabled by default for projects. You have to enable it in the
  global security configuration page.
* [JENKINS-30574](https://issues.jenkins-ci.org/browse/JENKINS-30574): Support global default authorization
strategy.
* [JENKINS-32769](https://issues.jenkins-ci.org/browse/JENKINS-32769): Displays an error when a 
built-in user is used for "Run as Specific User".

### Fixed
* **SECURITY FIX** [JENKINS-28298](https://issues.jenkins-ci.org/browse/JENKINS-28298): Reject 
unauthenticated configurations via REST / CLI.
  * See [JENKINS-28298](https://wiki.jenkins.io/display/JENKINS/JENKINS-28298) for details.

### Changed
* **Targets Jenkins 1.625.**


## [1.1.0] - 2015-08-09

### Added
* [JENKINS-28298](https://issues.jenkins-ci.org/browse/JENKINS-28298): Added a feature to enable / disable strategies.
  * **"Run as Specific User" is disabled by default.** You need to   enable it after upgrading from a prior version if you use it.
* [JENKINS-26670](https://issues.jenkins-ci.org/browse/JENKINS-26670): Supports workflow.
* [JENKINS-22470](https://issues.jenkins-ci.org/browse/JENKINS-22470): Supports apitoken for authentication. 
* [JENKINS-25403](https://issues.jenkins-ci.org/browse/JENKINS-25403): Add support for upcoming `$class` annotation change.

## [1.0.3] - 2014-04-14

### Fixed
* **SECURITY FIX** [JENKINS-22469](https://issues.jenkins-ci.org/browse/JENKINS-22469): Authentication
of "Run as Specific User" is easily bypassed by REST/CLI added. 
* [JENKINS-20786](https://issues.jenkins-ci.org/browse/JENKINS-20786): Replaced radio buttons to dropdown 
selecting authorization strategies .

## [1.0.2] - 2014-02-22

### Added
* ([JENKINS-20812](https://issues.jenkins-ci.org/browse/JENKINS-20812):`AuthorizeProjectStrategyDescriptor` 
not to send the password value to test whether password is required.

## [1.0.1] - 2013-11-30

### Fixed
* [JENKINS-20784](https://issues.jenkins-ci.org/browse/JENKINS-20784): Problem that a new user created
if you authenticate with non-existent user.
* [JENKINS-20785](https://issues.jenkins-ci.org/browse/JENKINS-20785): Works with `MatrixProject`.

## [1.0.0] - 2013-11-24

### Added
* Initial release.
