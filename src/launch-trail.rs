//! A simple and secure release management for Internet Computer projects.
//!
//! does two things:
//!
//!  1. Schedule, execute, or revoke an action that is essentially an update call to any canister.
//!
//!  2. Keep a complete record of all actions and their execution results.
//!
//! A project can use an immutable LaunchTrail canister to create and manage other canisters in a secure and verifiable manner.
//!
//! Please see <https://github.com/spinner-cash/launch-trail> for more information.
use hex::FromHex;
use ic_cdk::export::{
    candid::{candid_method, CandidType},
    serde::{Deserialize, Serialize},
    Principal,
};
use ic_cdk_macros::*;
use spnr_lib::{
    log::{Log, LogState},
    storage::{StableStorage, StorageStack},
};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

const MAX_VIEW_RANGE: u64 = 1024;

/// Initial configuration.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Default)]
pub struct InitialConfig {
    /// Number of entries in a bucket.
    pub bucket_size: usize,
    /// Maximum number of buckets.
    pub max_buckets: usize,
    /// Configuration that can be modified at run time.
    pub config: Config,
}

/// Adjustable configuration.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Default)]
pub struct Config {
    /// Minimum schedule delay, in nano-seconds.
    pub min_schedule: Time,
    /// List of principals who can call submit.
    pub submitters: Vec<Principal>,
    /// List of principals who can call revoke.
    pub revokers: Vec<Principal>,
}

/// nano second since UNIX Epoch.
pub type Time = u64;

/// Index of a record in the log.
pub type Index = u64;

/// A Blob type with fast serialization through [serde_bytes].
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Default)]
pub struct Blob(#[serde(with = "serde_bytes")] Vec<u8>);

/// Schedule is either an absolute time or a relative time.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Hash, PartialEq)]
pub enum Schedule {
    /// Exactly at the given time.
    At(Time),
    /// At curent time + the given time interval.
    In(Time),
}

impl Default for Schedule {
    fn default() -> Self {
        Self::At(0)
    }
}

/// Action contains both data of the actual call, and meta data about the call.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Hash, PartialEq)]
pub struct Action {
    /// Activation time, after which an action can be executed.
    pub activates: Schedule,
    /// Expiration time, after which an action can no longer be executed.
    pub expires: Schedule,
    /// Canister to call.
    pub canister: Principal,
    /// Method of the canister to call.
    pub method: String,
    /// SHA-256 checksum (hex string) of the call argument. The actual argument will be required and checked in the execute call.
    pub sha256: Option<String>,
    /// URL to the documentation of this action.
    pub url: String,
    /// Cycle payment for the call.
    pub payment: u128,
    /// List of prerequisite actions, i.e. they have to be successfully executed before this one can be executed.
    pub requires: Vec<Index>,
    /// Principals that are allowed to execute this action. Default to submitters if `None`.
    pub executors: Option<Vec<Principal>>,
    /// Principals that are allowed to revoke this action. Default to submitters if `None`.
    pub revokers: Option<Vec<Principal>>,
}

impl Default for Action {
    fn default() -> Self {
        Self {
            activates: Schedule::default(),
            expires: Schedule::default(),
            canister: Principal::anonymous(),
            method: String::new(),
            sha256: None,
            url: String::new(),
            payment: 0,
            requires: Vec::new(),
            executors: None,
            revokers: None,
        }
    }
}

impl Action {
    /// Return the activation time.
    pub fn activation(&self, now: Time) -> Time {
        match self.activates {
            Schedule::At(t) => t,
            Schedule::In(t) => now + t,
        }
    }
    /// Return the expiration time.
    pub fn expiration(&self, now: Time) -> Time {
        match self.expires {
            Schedule::At(t) => t,
            Schedule::In(t) => now + t,
        }
    }
    /// An action is considered active at the given time `now` if it has an activation time that is less or equal, and it is no expired.
    pub fn is_active(&self, now: Time) -> bool {
        self.activation(now) <= now && !self.is_expired(now)
    }
    /// An action is considered expired at the given time `now` if it has an expiration time that is less.
    pub fn is_expired(&self, now: Time) -> bool {
        self.expiration(now) < now
    }
}

/// An recorded log entry item is either an `Action`, or its execution result (`Reponse` or `Error`).
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Hash, PartialEq)]
pub enum Item {
    Action(Action),
    Response(Index, Blob),
    Error(Index, i32, String),
}

/// A record is just an item and its recorded time.
#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Hash, PartialEq)]
pub struct Record {
    time: Time,
    caller: Option<Principal>,
    item: Item,
}

type Records<'a, Storage> = Log<'a, Storage, (Record,)>;

/// In-memory state maintains the following invariant:
/// 1. Non-expired messages are always kept in the state.
/// 2. Results of all prerequisites of non-executed and non-expired messages are always kept in the state.
#[derive(Default)]
struct State {
    /// Append-only log state of all records.
    /// All logs are stored in stable memory and are arranged only in a partial order:
    /// an `Action` comes before its corresponding `Response` or `Error`.
    log: LogState,
    /// Non-expired and non-executed actions.
    actions: BTreeMap<Index, Action>,
    /// Results of executed actions.
    results: BTreeMap<Index, ic_cdk::api::call::CallResult<Blob>>,
}

impl State {
    fn new<S: StorageStack>(mut log_state: LogState, storage: &mut S, first: u64) -> Self {
        let log: Records<'_, S> = Log::new(&mut log_state, storage);
        let mut actions = BTreeMap::default();
        let mut results = BTreeMap::default();
        for i in first..log.size() {
            match log
                .get(i)
                .unwrap_or_else(|| panic!("Log at {} is corrupted", i))
                .0
                .item
            {
                Item::Action(action) => {
                    actions.insert(i, action);
                }
                Item::Response(i, blob) => {
                    if actions.remove(&i).is_some() {
                        results.insert(i, Ok(blob));
                    }
                }
                Item::Error(i, code, msg) => {
                    if actions.remove(&i).is_some() {
                        results.insert(i, Err((ic_cdk::api::call::RejectionCode::from(code), msg)));
                    }
                }
            }
        }
        Self {
            log: log_state,
            actions,
            results,
        }
    }

    /// Return the least index of actions that are still required by other actions in the state.
    fn least_required(&self) -> Option<Index> {
        let mut required = BTreeSet::new();
        for action in self.actions.values() {
            for i in action.requires.iter() {
                required.insert(*i);
            }
        }
        required.iter().next().cloned()
    }

    /// Return the least index in the log from which the state should be read.
    fn least_index(&self) -> Index {
        let i = self.log.size;
        let j = self.actions.keys().next().cloned().unwrap_or(i);
        let k = self.least_required().unwrap_or(i);
        j.min(k)
    }

    /// Prune expired actions from the given state, and record them in the log.
    fn prune<S: StorageStack>(&mut self, storage: &mut S, now: Time) -> Result<(), &'static str> {
        let mut log: Records<'_, S> = Log::new(&mut self.log, storage);
        // prune expired actions
        for (index, action) in self.actions.iter() {
            if action.is_expired(now) {
                let item = Item::Error(*index, 0, "Expired".to_string());
                log.push((Record {
                    time: now,
                    item,
                    caller: None,
                },))
                    .ok_or("CapacityFull")?;
                self.results.insert(
                    *index,
                    Err((
                        ic_cdk::api::call::RejectionCode::from(0),
                        "Expired".to_string(),
                    )),
                );
            }
        }
        self.actions.retain(|_, value| !value.is_expired(now));
        // prune not needed results
        if let Some(least_required) = self.least_required() {
            self.results = self.results.split_off(&least_required);
        } else {
            self.results = BTreeMap::new()
        }
        Ok(())
    }
}

thread_local! {
    static CONFIG : RefCell<Config> = RefCell::new(Config::default());
    static STATE : RefCell<State> = RefCell::new(State::default());
}

fn trap<T>(err: String) -> T {
    ic_cdk::api::trap(&err)
}

fn trap_io<T>(err: std::io::Error) -> T {
    trap(format!("{}", err))
}

#[init]
#[candid_method(init)]
fn init(initial_config: InitialConfig) {
    STATE.with(|state| {
        state.borrow_mut().log =
            LogState::new(0, initial_config.bucket_size, initial_config.max_buckets);
    });
    CONFIG.with(|config| config.replace(initial_config.config));
}

#[pre_upgrade]
fn pre_upgrade() {
    let config = CONFIG.with(|config| config.replace(Config::default()));
    let state = STATE.with(|state| state.replace(State::default()));
    let mut storage = StableStorage::new().new_with(state.log.offset);
    let least = state.least_index();
    storage
        .push((config, state.log, least))
        .unwrap_or_else(trap_io);
    storage.finalize().unwrap_or_else(trap_io);
}

#[post_upgrade]
fn post_upgrade() {
    //ic_cdk::println!("in post upgrade");
    let mut storage = StableStorage::new();
    let (config, log_state, first) = storage
        .pop::<(Config, LogState, Index)>()
        .unwrap_or_else(trap_io);
    CONFIG.with(|c| c.replace(config));
    STATE.with(|s| s.replace(State::new(log_state, &mut storage, first)));
}

/// Public stats.
#[derive(CandidType, Serialize, Debug)]
pub struct Stats {
    config: Config,
    current_time: u64,
    number_of_entries: u64,
    max_entries_allowed: u64,
    total_bytes_used: u64,
    max_view_range: u64,
    first_in_memory_index: u64,
    scheduled_actions: usize,
    active_actions: usize,
}

#[query]
#[candid_method(query)]
async fn stats() -> Stats {
    CONFIG.with(|config| {
        STATE.with(|s| {
            let state = s.borrow();
            let now = ic_cdk::api::time();
            Stats {
                config: config.borrow().clone(),
                current_time: now,
                number_of_entries: state.log.size,
                total_bytes_used: state.log.offset,
                max_entries_allowed: state.log.bucket_size as u64 * state.log.max_buckets as u64,
                max_view_range: MAX_VIEW_RANGE,
                first_in_memory_index: state.least_index(),
                scheduled_actions: state
                    .actions
                    .values()
                    .filter(|action| !action.is_expired(now))
                    .count(),
                active_actions: state
                    .actions
                    .values()
                    .filter(|action| action.is_active(now))
                    .count(),
            }
        })
    })
}

fn lookup<S: StorageStack>(
    state: &mut State,
    storage: &mut S,
    start_index: u64,
    end_index: u64,
) -> Vec<Record> {
    let log_state = &mut state.log;
    let log: Records<'_, S> = Log::new(log_state, storage);
    let mut entries = Vec::with_capacity((end_index - start_index) as usize);
    for i in start_index..(end_index.min(log.size())) {
        match log.get(i) {
            Some(entry) => entries.push(entry.0),
            None => break,
        };
    }
    entries
}

#[query]
#[candid_method(query)]
async fn records(start_index: u64, end_index: u64) -> Vec<Record> {
    assert!(end_index > start_index);
    assert!(end_index - start_index < MAX_VIEW_RANGE);
    STATE.with(|state| {
        lookup(
            &mut state.borrow_mut(),
            &mut StableStorage::new(),
            start_index,
            end_index,
        )
    })
}

#[update]
#[candid_method(update)]
async fn configure(config: Config) {
    // Only this canister is allowed to call configure on itself.
    assert_eq!(ic_cdk::api::caller(), ic_cdk::api::id(), "Unauthorized");
    CONFIG.with(|c| c.replace(config));
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Hash, PartialEq)]
pub enum SubmitError {
    ActivatesTooSoon,
    CapacityFull,
    InvalidExpires,
    InvalidChecksum,
    InvalidRequires(Index),
    Unauthorized,
}

fn assert<Err>(condition: bool, err: Err) -> Result<(), Err> {
    if condition {
        Ok(())
    } else {
        Err(err)
    }
}

fn submit_action<S: StorageStack>(
    config: &Config,
    state: &mut State,
    storage: &mut S,
    time: Time,
    caller: Principal,
    mut action: Action,
) -> Result<Index, SubmitError> {
    use SubmitError::*;
    assert(config.submitters.iter().any(|x| x == &caller), Unauthorized)?;
    assert(
        action.expiration(time) > action.activation(time),
        InvalidExpires,
    )?;
    assert(
        action.activation(time) >= time + config.min_schedule,
        ActivatesTooSoon,
    )?;
    // Prune before we check requires
    state.prune(storage, time).map_err(|_| CapacityFull)?;
    // All that in requires must be either scheduled or active.
    for i in action.requires.iter() {
        assert(state.actions.get(i).is_some(), InvalidRequires(*i))?;
    }
    // Check if sha256 is a valid hex string if it is provided.
    if let Some(sha256) = &action.sha256 {
        <[u8; 32]>::from_hex(sha256.clone()).map_err(|_| InvalidChecksum)?;
    }
    // Change the action to use absolute time.
    action.activates = Schedule::At(action.activation(time));
    action.expires = Schedule::At(action.expiration(time));
    // Log and then insert to state
    let item = Item::Action(action.clone());
    let log_state = &mut state.log;
    let mut log: Records<'_, S> = Log::new(log_state, storage);
    let index = log.size();
    let caller = Some(caller);
    log.push((Record { time, item, caller },))
        .ok_or(CapacityFull)?;
    state.actions.insert(index, action);
    Ok(index)
}

#[update]
#[candid_method(update)]
async fn submit(action: Action) -> Result<Index, SubmitError> {
    CONFIG.with(|c| {
        STATE.with(|s| {
            submit_action(
                &c.borrow(),
                &mut s.borrow_mut(),
                &mut StableStorage::new(),
                ic_cdk::api::time(),
                ic_cdk::api::caller(),
                action,
            )
        })
    })
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Hash, PartialEq)]
pub struct ExecuteArgs {
    index: Index,
    args: Blob,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Hash, PartialEq)]
pub enum ExecuteError {
    NotFoundOrExpired,
    Expired,
    Inactive,
    InvalidChecksum,
    ChecksumMismatch,
    Unauthorized,
    RequiresNotOk(Index),
    CapacityFull,
}

fn pre_execute(
    config: &Config,
    state: &mut State,
    now: Time,
    caller: Principal,
    args: &ExecuteArgs,
) -> Result<(Principal, String, u128), ExecuteError> {
    use ExecuteError::*;
    let action = state.actions.get(&args.index).ok_or(NotFoundOrExpired)?;
    assert(!action.is_expired(now), Expired)?;
    assert(action.is_active(now), Inactive)?;
    let checksum = hmac_sha256::Hash::hash(&args.args.0);
    if let Some(sha256) = &action.sha256 {
        let sha256 = <[u8; 32]>::from_hex(sha256).map_err(|_| InvalidChecksum)?;
        assert(checksum == sha256, ChecksumMismatch)?;
    }
    let executors = action
        .executors
        .clone()
        .unwrap_or_else(|| config.submitters.clone());
    assert(executors.iter().any(|x| x == &caller), Unauthorized)?;
    for i in action.requires.iter() {
        assert(
            matches!(state.results.get(i), Some(Ok(_))),
            RequiresNotOk(*i),
        )?
    }
    let result = (action.canister, action.method.clone(), action.payment);
    state.actions.remove(&args.index);
    Ok(result)
}

fn post_execute<S: StorageStack>(
    state: &mut State,
    storage: &mut S,
    time: Time,
    caller: Principal,
    index: Index,
    result: Result<Blob, (ic_cdk::api::call::RejectionCode, String)>,
) -> Result<Result<Blob, (i32, String)>, ExecuteError> {
    state.results.insert(index, result.clone());
    let log_state = &mut state.log;
    let mut log: Records<'_, S> = Log::new(log_state, storage);
    let item = match result.clone() {
        Ok(blob) => Item::Response(index, blob),
        Err((code, error)) => Item::Error(index, code as i32, error),
    };
    let caller = Some(caller);
    log.push((Record { time, item, caller },))
        .ok_or(ExecuteError::CapacityFull)?;
    Ok(result.map_err(|(code, error)| (code as i32, error)))
}

#[update]
#[candid_method(update)]
async fn execute(args: ExecuteArgs) -> Result<Result<Blob, (i32, String)>, ExecuteError> {
    let caller = ic_cdk::api::caller();
    let (id, method, payment) = CONFIG.with(|c| {
        STATE.with(|s| {
            pre_execute(
                &c.borrow(),
                &mut s.borrow_mut(),
                ic_cdk::api::time(),
                caller,
                &args,
            )
        })
    })?;
    let result = ic_cdk::api::call::call_raw128(id, &method, &args.args.0, payment)
        .await
        .map(Blob);
    STATE.with(|s| {
        post_execute(
            &mut s.borrow_mut(),
            &mut StableStorage::new(),
            ic_cdk::api::time(),
            caller,
            args.index,
            result,
        )
    })
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Hash, PartialEq)]
pub struct RevokeArgs {
    index: Index,
    reason: String,
}

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, Hash, PartialEq)]
pub enum RevokeError {
    NotFoundOrExpired,
    Expired,
    Unauthorized,
    CapacityFull,
}

fn revoke_action<S: StorageStack>(
    config: &Config,
    state: &mut State,
    storage: &mut S,
    time: Time,
    caller: Principal,
    args: &RevokeArgs,
) -> Result<(), RevokeError> {
    use RevokeError::*;
    let action = state.actions.get(&args.index).ok_or(NotFoundOrExpired)?;
    assert(!action.is_expired(time), Expired)?;
    let revokers = action
        .revokers
        .clone()
        .unwrap_or_else(|| config.submitters.clone());
    let mut revokers = revokers.iter().chain(config.revokers.iter());
    assert(revokers.any(|x| x == &caller), Unauthorized)?;
    let reason = format!("Cancelled: {}", args.reason);
    state.results.insert(
        args.index,
        Err((ic_cdk::api::call::RejectionCode::from(0), reason.clone())),
    );
    let log_state = &mut state.log;
    let mut log: Records<'_, S> = Log::new(log_state, storage);
    let item = Item::Error(args.index, 0, reason);
    let caller = Some(caller);
    log.push((Record { time, item, caller },))
        .ok_or(CapacityFull)?;
    state.actions.remove(&args.index);
    Ok(())
}

#[update]
#[candid_method(update)]
async fn revoke(args: RevokeArgs) -> Result<(), RevokeError> {
    CONFIG.with(|c| {
        STATE.with(|s| {
            revoke_action(
                &c.borrow(),
                &mut s.borrow_mut(),
                &mut StableStorage::new(),
                ic_cdk::api::time(),
                ic_cdk::api::caller(),
                &args,
            )
        })
    })
}

candid::export_service!();
#[query]
#[candid_method(query)]
fn __get_candid_interface_tmp_hack() -> String {
    __export_service()
}

#[cfg(not(any(target_arch = "wasm32", test)))]
fn main() {
    std::print!("{}", __export_service());
}

#[cfg(any(target_arch = "wasm32", test))]
fn main() {}

#[cfg(test)]
mod test {
    use super::*;
    use spnr_lib::storage::test::Stack;

    fn action(activates: Time, expires: Time, requires: Vec<Index>) -> Action {
        Action {
            activates: Schedule::At(activates),
            expires: Schedule::At(expires),
            requires,
            ..Default::default()
        }
    }

    #[test]
    fn test_state() {
        let mut log_state = LogState::new(0, 10, 10);
        let mut storage = Stack::default();
        // Prepare some log entries
        let mut log: Records<'_, Stack> = Log::new(&mut log_state, &mut storage);
        let caller = None;
        log.push((Record {
            time: 0,
            item: Item::Action(action(5, 10, vec![])),
            caller,
        },));
        log.push((Record {
            time: 3,
            item: Item::Action(action(6, 15, vec![0])),
            caller,
        },));
        log.push((Record {
            time: 11,
            item: Item::Error(0, 0, "Expired".into()),
            caller,
        },));
        log.push((Record {
            time: 13,
            item: Item::Action(action(14, 20, vec![1])),
            caller,
        },));
        let mut state = State::new(log_state, &mut storage, 0);
        assert_eq!(state.actions.len(), 2); // action 0 expired
        assert_eq!(state.results.len(), 1); // result 0 still required

        state.prune(&mut storage, 14).unwrap();
        assert_eq!(state.actions.len(), 2); // action 1 not expired
        assert_eq!(state.results.len(), 1); // result 0 still required
        assert_eq!(state.least_index(), 0);

        state.prune(&mut storage, 17).unwrap();
        assert_eq!(state.actions.len(), 1); // action 1 expired
        assert_eq!(state.results.len(), 1); // result 0 pruned
        assert_eq!(state.least_index(), 1); // result 1 still required
        assert_eq!(state.log.size, 5);

        let log: Records<'_, Stack> = Log::new(&mut state.log, &mut storage);
        assert_eq!(log.size(), 5);
        assert!(matches!(
            log.get(4),
            Some((Record {
                time: _,
                caller: _,
                item: Item::Error(1, 0, _)
            },))
        ));

        // test the new function from least index 1
        let log_state = state.log.clone();
        let mut state = State::new(log_state, &mut storage, 1);
        assert_eq!(state.actions.len(), 1);
        assert_eq!(state.results.len(), 1);
        assert_eq!(state.least_index(), 1);

        // prune again
        state.prune(&mut storage, 21).unwrap();
        assert_eq!(state.actions.len(), 0); // all pruned
        assert_eq!(state.results.len(), 0); // all pruned
        assert_eq!(state.least_index(), 6);
        assert_eq!(state.log.size, 6);
    }

    #[test]
    fn test_submit() {
        use SubmitError::*;
        let p = Principal::from_text("aaaaa-aa").unwrap();
        let q = Principal::from_text("2chl6-4hpzw-vqaaa-aaaaa-c").unwrap();
        let config = Config {
            min_schedule: 20,
            submitters: vec![q],
            revokers: vec![],
        };
        let log_state = LogState::new(0, 10, 10);
        let mut storage = Stack::default();
        let mut state = State::new(log_state, &mut storage, 0);
        let mut submit_ = |t, c, a| submit_action(&config, &mut state, &mut storage, t, c, a);
        assert_eq!(submit_(0, p, action(5, 10, vec![])), Err(Unauthorized));
        assert_eq!(submit_(0, q, action(10, 5, vec![])), Err(InvalidExpires));
        assert_eq!(submit_(0, q, action(5, 10, vec![])), Err(ActivatesTooSoon));
        assert_eq!(submit_(0, q, action(20, 30, vec![])), Ok(0));
        assert_eq!(submit_(0, q, action(25, 35, vec![0])), Ok(1));
        assert_eq!(submit_(32, q, action(55, 60, vec![1])), Ok(3)); // result 0 takes up space
        assert_eq!(
            submit_(32, q, action(60, 65, vec![0])),
            Err(InvalidRequires(0))
        );
        assert_eq!(state.actions.len(), 2);
        assert_eq!(state.results.len(), 1);

        let mut submit_ = |t, c, a| submit_action(&config, &mut state, &mut storage, t, c, a);
        assert_eq!(
            submit_(36, q, action(65, 70, vec![1])),
            Err(InvalidRequires(1))
        );
        assert_eq!(submit_(36, q, action(65, 70, vec![3])), Ok(5));
        assert_eq!(state.least_index(), 1);

        let mut state = State::new(state.log.clone(), &mut storage, 1);
        assert_eq!(state.actions.len(), 2); // action 3 and 5
        assert_eq!(state.results.len(), 1); // result 1
        assert_eq!(state.least_index(), 1);

        let mut submit_ = |t, c, a| submit_action(&config, &mut state, &mut storage, t, c, a);
        assert_eq!(submit_(40, q, action(65, 70, vec![])), Ok(6));
        assert_eq!(state.actions.len(), 3); // action 3, 5 and 6
        assert_eq!(state.results.len(), 1); // result 1
        assert_eq!(state.least_index(), 1);
        assert_eq!(state.log.size, 7); // action: 0,1,3,5,6 results: 0,1

        let mut submit_ = |t, c, a| submit_action(&config, &mut state, &mut storage, t, c, a);
        assert_eq!(submit_(61, q, action(85, 90, vec![])), Ok(8));
        assert_eq!(state.actions.len(), 3); // action 5,6,7
        assert_eq!(state.results.len(), 1); // result 3
        assert_eq!(state.least_index(), 3);
    }

    #[test]
    fn test_execute() {
        use ExecuteError::*;
        let p = Principal::from_text("aaaaa-aa").unwrap();
        let q = Principal::from_text("2chl6-4hpzw-vqaaa-aaaaa-c").unwrap();
        let config = Config {
            min_schedule: 20,
            submitters: vec![q],
            revokers: vec![],
        };
        let log_state = LogState::new(0, 10, 10);
        let mut storage = Stack::default();
        let mut state = State::new(log_state, &mut storage, 0);
        let arg = |index| ExecuteArgs {
            index,
            args: Blob::default(),
        };
        let mut submit_ = |t, c, a| submit_action(&config, &mut state, &mut storage, t, c, a);
        assert_eq!(submit_(0, q, action(20, 35, vec![])), Ok(0));
        assert_eq!(submit_(0, q, action(30, 40, vec![0])), Ok(1));
        let mut pre = |t, c, i| pre_execute(&config, &mut state, t, c, &arg(i));
        assert_eq!(pre(26, p, 3), Err(NotFoundOrExpired));
        assert_eq!(pre(10, p, 0), Err(Inactive));
        assert_eq!(pre(40, p, 0), Err(Expired));
        assert_eq!(pre(20, p, 0), Err(Unauthorized));
        assert_eq!(pre(30, q, 1), Err(RequiresNotOk(0)));
        // execute action 0
        assert!(matches!(pre(30, q, 0), Ok((_, _, _))));
        let mut post = |i, t, c, r| post_execute(&mut state, &mut storage, t, c, i, r);
        assert!(matches!(post(0, 33, q, Ok(Blob::default())), Ok(_)));
        assert_eq!(state.actions.len(), 1);
        assert_eq!(state.results.len(), 1);
        // execute action 1
        let mut pre = |t, c, i| pre_execute(&config, &mut state, t, c, &arg(i));
        assert!(matches!(pre(33, q, 1), Ok((_, _, _))));
        let mut post = |i, t, c, r| post_execute(&mut state, &mut storage, t, c, i, r);
        let code = ic_cdk::api::call::RejectionCode::Unknown;
        assert!(matches!(
            post(1, 35, q, Err((code, "Unknown".into()))),
            Ok(_)
        ));
        assert_eq!(state.actions.len(), 0);
        assert_eq!(state.results.len(), 2);
    }

    #[test]
    fn test_checksum() {
        let q = Principal::from_text("2chl6-4hpzw-vqaaa-aaaaa-c").unwrap();
        let config = Config {
            min_schedule: 20,
            submitters: vec![q],
            revokers: vec![],
        };
        let log_state = LogState::new(0, 10, 10);
        let mut storage = Stack::default();
        let mut state = State::new(log_state, &mut storage, 0);
        let mut submit_ = |t, c, a| submit_action(&config, &mut state, &mut storage, t, c, a);
        let mut a0 = action(20, 35, vec![]);
        a0.sha256 = Some("123456abcdef".into());
        assert_eq!(submit_(0, q, a0.clone()), Err(SubmitError::InvalidChecksum));
        a0.sha256 = Some("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824".into());
        assert_eq!(submit_(0, q, a0), Ok(0));
        let mut pre = |t, c, a| pre_execute(&config, &mut state, t, c, a);
        let arg = ExecuteArgs {
            index: 0,
            args: Blob::default(),
        };
        assert_eq!(pre(26, q, &arg), Err(ExecuteError::ChecksumMismatch));
        let arg = ExecuteArgs {
            index: 0,
            args: Blob("hello".as_bytes().to_vec()),
        };
        assert!(matches!(pre(26, q, &arg), Ok(_)));
    }

    #[test]
    fn test_revoke() {
        use RevokeError::*;
        let p = Principal::from_text("aaaaa-aa").unwrap();
        let q = Principal::from_text("2chl6-4hpzw-vqaaa-aaaaa-c").unwrap();
        let config = Config {
            min_schedule: 20,
            submitters: vec![q],
            revokers: vec![],
        };
        let log_state = LogState::new(0, 10, 10);
        let mut storage = Stack::default();
        let mut state = State::new(log_state, &mut storage, 0);
        let arg = |index| RevokeArgs {
            index,
            reason: String::new(),
        };
        let mut submit_ = |t, c, a| submit_action(&config, &mut state, &mut storage, t, c, a);
        assert_eq!(submit_(0, q, action(20, 35, vec![])), Ok(0));
        assert_eq!(submit_(0, q, action(30, 40, vec![0])), Ok(1));
        let mut revoke_ = |t, c, i| revoke_action(&config, &mut state, &mut storage, t, c, &arg(i));
        assert_eq!(revoke_(26, p, 3), Err(NotFoundOrExpired));
        assert_eq!(revoke_(10, p, 0), Err(Unauthorized));
        assert_eq!(revoke_(36, q, 0), Err(Expired));
        assert_eq!(revoke_(36, q, 1), Ok(()));
    }
}
