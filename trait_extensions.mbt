///|
pub extend PemError with Eq::{equal, not_equal}

///|
pub extend PemError with ToJson::{to_json}

///|
pub extend PemBlock with Eq::{equal, not_equal}

///|
pub extend PemError with Show::{output, to_string}

///|
pub extend PemBlock with Show::{output, to_string}
