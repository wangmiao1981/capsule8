## 0.3.0-alpha (Dec 29, 2017)

BACKWARDS INCOMPATIBILITIES:

  * Configuration variables were renamed and some were removed in [#92](https://github.com/capsule8/capsule8/pull/92)

FEATURES:

  * Allow TLS configuration for telemetry server ([#91](https://github.com/capsule8/capsule8/pull/91))
  * Enable syscall args in API and in functional test ([#86](https://github.com/capsule8/capsule8/pull/86))
  * Use a kprobe to track process command-line information ([#80](https://github.com/capsule8/capsule8/pull/80))
  * Properly retrieve syscall arguments and add support for filtering on them ([#78](https://github.com/capsule8/capsule8/pull/78))

IMPROVEMENTS:

  * Refactor CI to use CircleCI 2.0 ([#90](https://github.com/capsule8/capsule8/pull/90))
  * Apply consistency to network endpoint address naming ([#92](https://github.com/capsule8/capsule8/pull/92))
  * Clean up all golint warnings ([#89](https://github.com/capsule8/capsule8/pull/89))
  * Make the process info cache size configurable ([#88](https://github.com/capsule8/capsule8/pull/88))
  * Move contributing guidelines and issue template into .github ([#87](https://github.com/capsule8/capsule8/pull/87))
  * Add issue template ([#84](https://github.com/capsule8/capsule8/pull/84))
  * Default to https for vendor submodule ([#83](https://github.com/capsule8/capsule8/pull/83))
  * Update vendoring of api and aws tools ([#79](https://github.com/capsule8/capsule8/pull/79))
  * Add make target to run the sensor in the background ([#73](https://github.com/capsule8/capsule8/pull/73))

BUG FIXES:

  * Fix regenerating code from .protos ([#85](https://github.com/capsule8/capsule8/pull/85))
  * Remove accidentally committed binary ([#81](https://github.com/capsule8/capsule8/pull/81))
  * Remove accidentally committed binaries ([#77](https://github.com/capsule8/capsule8/pull/77))

## 0.2.1-alpha (Dec 29, 2017)

BACKWARDS INCOMPATIBILITIES:

  None

FEATURES:

  None

IMPROVEMENTS:

  * Add make target to run the sensor in the background ([#73](https://github.com/capsule8/capsule8/pull/73))

BUG FIXES:

  * Remove accidentally committed binary and update vendoring ([#82](https://github.com/capsule8/capsule8/pull/82))
  * Remove accidentally committed binaries ([#77](https://github.com/capsule8/capsule8/pull/77))

## 0.2.0-alpha (Dec 14, 2017)

BACKWARDS INCOMPATIBILITIES:

  * Event filtering changed in [#55](https://github.com/capsule8/capsule8/pull/55) with updates to the underlying API definitions.

FEATURES:

  * Default to system wide event monitor even when running in container ([#62](https://github.com/capsule8/capsule8/pull/62))
  * Use single event monitor for all subscriptions ([#61](https://github.com/capsule8/capsule8/pull/61))
  * Use expression filtering from API for event based filtering ([#55](https://github.com/capsule8/capsule8/pull/55))
  * Add process credential tracking ([#57](https://github.com/capsule8/capsule8/pull/57))

IMPROVEMENTS:

  * Add copyright statement and license to all source files ([#76](https://github.com/capsule8/capsule8/pull/76))
  * Add kinesis telemetry ingestor example ([#71](https://github.com/capsule8/capsule8/pull/71))
  * Refactor network functional tests ([#72](https://github.com/capsule8/capsule8/pull/72))
  * Import telemetry API definitions that used to be vendored, directly to this respository ([#70](https://github.com/capsule8/capsule8/pull/70))
  * Create docker image for functional testing ([#63](https://github.com/capsule8/capsule8/pull/63))
  * Separate our sensor start and stop logic ([#68](https://github.com/capsule8/capsule8/pull/68))
  * Update service constructors to pass sensor reference ([#66](https://github.com/capsule8/capsule8/pull/66))
  * Add functional testing for network, syscall and kernelcall events ([#54](https://github.com/capsule8/capsule8/pull/54))
  * Update expression use to programmatically create expression trees ([#60](https://github.com/capsule8/capsule8/pull/60))
  * Improve and add to unit testing of /proc/[pid]/cgroup parsing ([#53](https://github.com/capsule8/capsule8/pull/53))
  * Remove sleeps in functional tests to make them more demanding ([#52](https://github.com/capsule8/capsule8/pull/52))
  * Use functions to configure the new event monitor input ([#37](https://github.com/capsule8/capsule8/pull/37))
  * Refactoring to set up the single event monitor work ([#31](https://github.com/capsule8/capsule8/pull/31))

BUG FIXES:

  * Fix identification of container IDs in a kubernetes environment ([#69](https://github.com/capsule8/capsule8/pull/69))
  * Fix duplicate events off by one error ([#64](https://github.com/capsule8/capsule8/pull/64))
  * Fix container information identification from Docker versions before 1.13.0 ([#56](https://github.com/capsule8/capsule8/pull/56))
  * Fix 'args' type information handling in various kernel versions ([#51](https://github.com/capsule8/capsule8/pull/51))


## 0.1.1-alpha (Dec 14, 2017)

BACKWARDS INCOMPATIBILITIES:

  None

FEATURES:

  None

IMPROVEMENTS:

  None

BUG FIXES:

  * Fix container information identification from Docker versions before 1.13.0 ([#65](https://github.com/capsule8/capsule8/pull/65))
  * Fix identification of container IDs in a kubernetes environment ([#67](https://github.com/capsule8/capsule8/pull/67))
