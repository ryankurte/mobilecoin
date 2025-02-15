# MobileCoin Fog

MobileCoin Fog is a privacy-preserving service designed to support use of the MobileCoin Payments Network on mobile devices,
which can use Fog to check their balance and send payments, without syncing the ledger.

Fog is designed so that the MobileCoin and Fog service operators have no nontrivial insight into your payment.
Please see the [threat model](../fog-threat-model-2.1.0.md) for a comprehensive explanation.

For an example Fog client written in rust, check out the [`fog-sample-paykit`](./sample-paykit).
For bindings used to support Java and Swift SDKs that support Fog clients in production,
check out the [`android-bindings`](../android-bindings) and [`libmobilecoin`](../libmobilecoin).

# Table of Contents
- [License](#license)
- [Cryptography Notice](#cryptography-notice)
- [Repository Structure](#repository-structure)
- [Build Instructions](#build-instructions)
- [Overview](#overview)
- [FAQ](#faq)
- [Support](#support)

## License
MobileCoin Fog is available under open-source licenses. Look for the *LICENSE* file in each crate for more information.

## Cryptography Notice
This distribution includes cryptographic software. Your country may have restrictions on the use of encryption software. Please check your country's laws before downloading or using this software.

#### Selected Binaries
| Target | Description |
| :-- | :-- |
| [`fog-ingest-server`](./ingest/server) | Obliviously post-processes the blockchain to organize transaction outputs according to fog hints.|
| [`fog-ledger-server`](./ledger/server) | Obliviously serves ledger materials such as rings, merkle proofs, and key images, used to verify whether a Txo was spent, or to construct new transactions. |
| [`fog-report-server`](./report/server) | Provides the ingest enclave's Attestation Verification Report for transaction construction. |
| [`fog-view-server`](./view/server) | Obliviously serves the post-processed Txos to clients who wish to check their balance and construct new transactions. |

## Build Instructions

The workspace can be built with `cargo build` and tested with `cargo test`. Either command will recognize the cargo `--release` flag to build with optimizations.

Some crates (e.g. [`fog-ingest-server`](./ingest/server)) depend on Intel SGX, which adds additional build and runtime requirements. For detailed information about setting up a build environment, how enclaves are built, and on configuring the build, see [BUILD.md](../BUILD.md).

For a quick start, you can build in the same docker image that we use for CI by using the `mob` tool. Note that this requires you to install [Docker](https://docs.docker.com/get-docker/). You can use the `mob` tool with the following commands:

```
# From the root of the cloned repository
./mob prompt

# At the resulting docker container prompt
cargo build
```

## Test Instructions

To run the unittest tests locally, you need to start a local postgres instance, then run the tests.  You can do this at the mob prompt:

```
# From the root of the cloned repository
./mob prompt

# Start postgres
sudo service postgresql start

# create a postgres user
sudo -u postgres createuser --superuser $USER

# Run the tests
cargo test
```

If you don't want to run the tests in docker, you can set up postgres locally, on Ubuntu, by following these instructions:

1. apt-get install postgresql postgresql-client postgresql-server-dev-all libpq-dev
2. Configure PostgreSQL to skip password authentication for local users - this is optional but simplifies local development.
    In order to do so, edit `/etc/postgresql/10/main/pg_hba.conf` and replace the following line:
        `host    all             all             127.0.0.1\/32            md5`
    with:
        `host    all             all             127.0.0.1\/32            trust`
   (See .circleci/config.yml for example on how this is done via a script)
3. Start the PostgreSQL server: `service postgresql start`
4. Create a PostgreSQL user that matches your current login username:
    `sudo -u postgres createuser --superuser $USER`
5. You should now be able to create a database: `createdb fog_test`
6. Install diesel-cli: `cargo install diesel_cli --no-default-features --features postgres`
7. To populate your newly created database with the fog tables, run this:
    `cd src/fog/sql_recovery_db && DATABASE_URL=postgres://$USER@localhost/fog_test diesel migration run`
8. Fog services that require connecting to the database need the DATABASE_URL environment variable set:
    `export DATABASE_URL=postgres://$USER@localhost/fog_test`
9. Running unit tests requires the TEST_DATABASE_URL environment variable:
    `export TEST_DATABASE_URL=postgres://localhost`
    Notice that it does not contain a database name - this gets automatically generated by the unit-test suite.

# Run the conformance tests

The conformance tests are an additional integration test which exercises the balance check procedure in a fog-client
implementation. The test is a python script that stands up all the fog services and drives them with MobileCoin ledgers
that are controlled by the test, in order to simulate various race conditions that can occur. Then the script asks the
fog-client what the balance is and watches for it to converge to the correct answer.

These tests can be validated by running them against the fog-sample-paykit, but they are intended to be run against
iOS and Android apps compiled for testing purposes.

To read about how to run the fog conformance tests, check their [README](../tools/fog-local-network).

## Overview

MobileCoin Fog is a suite of microservices designed to enable MobileCoin payments on mobile devices.

For MobileCoin payments to be practical, we cannot require the mobile device to
sync the ledger or download the entire blockchain. However, a so-called "thin wallet" won't
work either, because the types of queries made by a thin wallet generally reveal to the
server the user's balance, when they got paid, etc. In typical thin wallet designs, the
server is trusted by the user.

MobileCoin has been engineered to eliminate this sort of trust in the service is "oblivious"
to the nature of the user requests, and the service operator is unable to harvest the users'
data in exchange for running the service.

Because of this, off-the-shelf solutions to wallet services simply don't work. In many cases,
if we naively make a database query to handle a query that a wallet would make if it had access
to the ledger, it reveals significant information about e.g. whether Bob was paid or not in the
last block, which payments Bob received, whether Alice paid Bob, etc., any of which would not
meet our privacy goals.

Instead, Fog makes heavy use of SGX enclaves and Oblivious RAM data structures to serve such
queries privately and without compromising scalability. Although such use of SGX may create
potential operational challenges, the MobileCoin system has been carefully designed to
navigate these challenges.

### Architecture

Fog works by post-processing the blockchain in an SGX-mediated way. Records are written to a
database (the "recovery database") which contains the entirety of information that a user needs to
recover all of their transactions privately.

Fog consists of four services:

  * The "fog-ingest" service consumes and post-processes the blockchain, writing records to the
    recovery database. The service attempts to decrypt the `e_fog_hint` field of each TxOut,
    and then tags that TxOut with a random number from a random number generator specific to
    the fog user who received the TxOut (if any). This is an SGX service, and these computations
    are performed obliviously. The service additionally
    publishes a public key to the "fog-report" service, for the users to use to create fog hints.

  * The "fog-view" service provides an API for fog users to access this database, whose primary
    purpose is to deliver to the fog users their TxOut's. Some of the
    queries that the user needs to make to the database are sensitive. To protect them, this
    is an SGX service and some of the queries are resolved obliviously.

  * The "fog-ledger" service provides several APIs for fog users to make queries against the
    MobileCoin ledger. Some of the queries that the user needs to make are sensitive; SGX also
    provides this service, and some of the queries are resolved obliviously.

  * The "fog-report" service. The fog report service publishes a signed fog public key which
    comes from the fog-ingest SGX enclave. This public key must be available to anyone
    who wants to send MobileCoin to a fog user, so the fog report service is expected to be
    publicly accessible and require no authentication (the way the others probably would).
    In addition to the Intel report, there is an X509 certificate chain signing the report as
    well. The "fog-report" service is not an SGX service.

## FAQ

1. Is Fog decentralized?

   Fog is a scalable service that helps users find their transactions, conduct balance checks,
   and build new transactions. Fog does so without requiring a local copy of the blockchain and without
   revealing a user's activities or giving away their private keys.

   Fog is intended to be run by app providers to provide their users with a private and positive mobile experience.
   Users need only trust the integrity of SGX, and not the service
   provider, for their privacy.

   Fog is thus not a single, decentralized network, but can be deployed as needed by each
   party willing to offer this service. Fog can be treated as critical infrastructure for an app, and can be scaled
   to meet each party's needs.

1. What is the hint field? Can I put anything in there?

   The purpose of the hint field is to send an encrypted message to the fog ingest enclave,
   which it finds when it post-processes the blockchain. A conforming
   client puts only an `mc-crypto-box` ciphertext of a specific size there. For non-fog
   transactions, a ciphertext encrypted for a random public key should be put there. Putting
   something in the hint field which is distinguishable from this may degrade privacy.

## Support

For troubleshooting help and other questions, please visit our [community forum](https://community.mobilecoin.foundation/).

You may also open a technical support ticket via [email](mailto:support@mobilecoin.foundation).

#### Trademarks

Intel and the Intel logo are trademarks of Intel Corporation or its subsidiaries. MobileCoin is a registered trademark
of MobileCoin Inc.
