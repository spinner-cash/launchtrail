///! A test canister.
use ic_cdk::export::candid::candid_method;
use ic_cdk_macros::*;

#[query]
#[candid_method(query)]
fn greet(name: String) -> String {
    format!("Hello, {}!", name)
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
