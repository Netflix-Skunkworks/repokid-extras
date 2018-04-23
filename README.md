Repokid
=======

[![NetflixOSS Lifecycle](https://img.shields.io/osslifecycle/Netflix/osstracker.svg)]()
[![Gitter chat](https://badges.gitter.im/gitterHQ/gitter.png)](https://gitter.im/netflix-repokid)

# Repokid Extras
Repokid Extras is a repository for helper scripts, plugins, and others for [Repokid](https://github.com/Netflix/repokid).
As a Skunkworks project these are not maintained or supported officially, but if you have questions you can ask in our Gitter
channel and we'll do our best to help you.

## cloudtrail-hook
CloudTrail hook is a reference implemenation of using [AWS CloudTrail](https://aws.amazon.com/cloudtrail/) to take away
permissions beyond the service level that Access Advisor provides.  In our implementation we are querying ElasticSearch, but
CloudTrail could be stored in other forms such as [Amazon Athena](https://aws.amazon.com/athena) as well.  The important part
is implementing the `DURING_REPOABLE_CALCULATION` hook and modifying the passed `potentially_repoable_permissions`.
