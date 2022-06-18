<div id="header" align="center"><img src="../../raw/main/icon/blue-on-white-outline.png" width="300"/></div>

#

**LaunchTrail: Simple and Secure Release Management for Internet Computer Projects**

![release](../../actions/workflows/release.yml/badge.svg)

There are many ways to configure and update canisters and services on the [Internet Computer].
But the challenge is how to do them in a secure and auditable manner, bringing more transparency and confidence to the community of a project.

LaunchTrail solves the problem by introducing the concept of "scheduled action": an action that is scheduled to take place at a future time.
The purpose is to give the public enough time to evaluate the impact and risk of an upcoming change:

- They can see it as safe and do nothing (i.e. wait for it to happen).
- They can see it as risky, and either
  - try to mitigate the risk for themselves, or
  - alert the community and developer, and hopefully have the "scheduled action" revoked.

All users are given a chance to evaluate the risk and benefit of something that is about to happen in order to make suitable plans and be self-responsible.

To achieve this, LaunchTrail has to (1) be immutable, and (2) keep a public record of everything it has done or is about to do, including creating new canisters, installing or upgrading their code, change their settings, so on and so forth.
Because LaunchTrail is trust-worthy, a project launched this way will have a verifiable history right from the start.

It is important to recognize that **LaunchTrail is not a form of governance** -- it is merely a tool, a means to an end, but not something you can replace governance with.

## How it works

A project can choose to deploy its own LaunchTrail canister to manage all other canisters.
A LaunchTrail canister mainly does two things:

1. Schedule, execute, or revoke an action.
2. Keep a complete record of all actions and their execution results.

An action is essentially an update call that is going to be executed by LaunchTrail.
The lifetime of an action is depicted below:

```
       /------> Revoked
      /
  Scheduled -----> Active -----> Executed
                      \
                       \-------> Expired
```

Once its scheduled time has passed, an action can no longer be revoked, and is given a time window to execute the call.
An action may also expire if its execution is never triggered.
Depending on how an action is configured, there are 3 roles:

- *Submitter*: who is allowed to schedule an action. Configured globally in the LaunchTrail canister settings.
- *Executor*: who is allowed to trigger the execution of an action. Configured per action.
- *Revoker*: who is allowed to revoke an action. Configured per action.

It is entirely up to the submitter to explain (via a URL link) what an action is going to do, and to convince people why it will be safe and secure to do so.

An action can specify a SHA-256 checksum of the actual call argument without having to expose it before execution time.
This allows developers to patch zero-day bugs, because the checksum can be retrospectively verified against the actual argument after an action is executed.

That being said, it is still recommended that a submitter provides both the checksum and the call argument ahead of time for people to verify.

## Usage

The first step is to [download a public release of lanchtrail.wasm](../../releases).

The latest SHA-256 hash of the `launchtrail.wasm` file should match the output below:

```
$ shasum -a 256 launchtrail.wasm
f14477489935a855e8cd417dec5374585da6c03432ad0142be3d2507cb9dd117  launchtrail.wasm
```

You can also fork this repo to have Github Actions build from source if you want to independently verify a release.

**Deploy LaunchTrail**

The fastest way to deploy is to download the `Makefile` from a release and run the following command (requires [GNU make] and [dfx]):

```
make deploy NETWORK=ic
```

This will download release binaries (see `RELEASE_TAG` in the Makefile), verify checksum, and deploy a canister using [dfx].
If all goes well, you will find the canister id of "launchtrail" in the `canister_ids.json` file created in the same directory.

Omit the `NETWORK=ic` part if you only want to test the deployment locally.

**Make LaunchTrail immutable**

It is only when LaunchTrail is immutable that people can trust its behavior is exactly as prescribed by its code and consequently trust the records it keeps.
This can be done by setting the controller of LaunchTrail to the [Black Hole] canister.
We can achieve the same purpose by removing all controllers, but only controllers of a canister can check its remaining cycle balance.
So using [Black Hole] is recommended.

```
dfx canister --network=ic update-settings launchtrail --controller e3mmv-5qaaa-aaaah-aadma-cai
```

It is no longer upgradable after this.

Next, we should keep an permanent record of the LaunchTrail canister info:

```
./dist/canister-info fetch $(dfx canister --network=ic id launchtrail) > launchtrail_info.json
./dist/canister-info verify < launchtrail_info.json
```

The `canister-info fetch` command fetches the (certificate of) canister info, and the `canister-info verify` command reads the info from stdin, and verifies its signature using IC's public key.
If successfully verified, it prints in human readable text the canister id, module hash, controllers, and creation time of this info (nano seconds since UNIX epoch).
This can serve as a proof that LaunchTrail was made immutable before the time stamp shown in the canister info.

Because this info is verifiable against the IC's public key, all records created by the LaunchTrail later will be trust-worthy because:

1. The LaunchTrail canister is immutable, We can be sure no one is able to change its code.
2. The LaunchTrail canister's module hash can be verified against a public release. We can check its source code and Github build process to confirm.
3. The LaunchTrail canister will record all scheduled actions and their execution results in an append only log stored in the canister's stable memory.

All action records can be retrieved programmatically by calling the `records(..)` method on the canister.
And a simple HTTP interface will be provided in a future release for even easier access.

**Deploy project canisters**

The LaunchTrail canister has a simple interface given below, and more details can be found in its [Candid file](./launchtrail.did).

```
service : (InitialConfig) -> {
  submit    : (Action) -> (variant { Ok : nat64; Err : SubmitError });
  execute   : (ExecuteArgs) -> (variant { Ok : Result; Err : ExecuteError });
  revoke    : (RevokeArgs) -> (variant { Ok; Err : RevokeError });
  configure : (Config) -> ();
  stats     : () -> (Stats) query;
  records   : (nat64, nat64) -> (vec Record) query;
}
```

We are working on a tool to help manage LaunchTrail actions and records, and will update this space once it is ready.

For now, you can look at how it is being used in [tests](./tests/) (requires [ic-repl]).

## FAQs

**Can we set LaunchTrail to be its own controller so that it can self-upgrade?**

No. Any upgrade to the LaunchTrail canister will destroy the trust in the records it keeps.
A possible attack is that a submitter can upgrade LaunchTrail to a malicious version that over-writes its existing records, and then upgrade again to a good version to hide the trail.
This kind of change will not be observable after the fact unless somebody can catch it in the moment.

A project wants to make sure *every action leaves a verifiable trail*.
Making LaunchTrail self-upgradable defeats this purpose.

**Is there a way to migrate canisters to newer versions of LaunchTrail?**

Yes. We can use LaunchTrail to change the controller of a canister to another LaunchTrail canister, possibly of a new version.
So projects can decide for themselves whether they want to upgrade as LaunchTrail develops new features.

**What is the recommended best practice to manage permissions?**

The developer of a project is in control of initial setup, so they can make their own choices.
But it is generally recommended that the developer takes the default *Submitter* and *Revoker* role.

The *Revoker* role, also requires a bit more caution.
At the moment a revoker can block any scheduled action, including actions that can change role settings.
We are working to improve this situation and hopefully bring more flexibility in a future release.

For canisters created through LaunchTrail, it is recommended to set their controller to only LaunchTrail.
This is to ensure all operations on these canisters have a verifiable track records.

**How to use LaunchTrail with SNS (Service Neuron Systems)?**

The current recommendation is to use LaunchTrail to deploy SNS, and have SNS be a *Revoker*.
Since SNS is not yet released, we will learn more details later.
But it is important to recognize that SNS does not replace LaunchTrail, nor vice versa.

## Build LaunchTrail from source

You will need [GNU make], [binaryen] and a Rust compiler toolchain such as [rustup] in PATH to build LaunchTrail from source.
Then you can type `make` in this project directory to build everything.

If you want to run canister tests (which requires [ic-repl]), you need to first start a dfx environment, for example:

```
make dfx.json
dfx start --background
make test
```

Please feel free to submit bug reports or feature requests on Github.
Pull requests are welcome too!

All source codes are original and released under [GPLv3](./LICENSE).
Please make sure you understand the requirement and risk before using them in your own projects.

[rustup]: https://rustup.rs
[dfx]: https://smartcontracts.org/docs/quickstart/1-quickstart.html
[GNU make]: https://www.gnu.org/software/make
[ic-repl]: https://github.com/chenyan2002/ic-repl
[binaryen]: https://github.com/WebAssembly/binaryen
[black hole]: https://github.com/ninegua/ic-blackhole
[Internet Computer]: https://wiki.internetcomputer.org
