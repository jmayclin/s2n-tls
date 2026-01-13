use std::sync::{
    atomic::{AtomicPtr, Ordering},
    mpsc::{self},
    Arc, Mutex,
};

mod static_lists;
