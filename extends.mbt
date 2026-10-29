///|
pub extend PemBlock with Eq::{not_equal, equal}

///|
pub extend PemBlock with Show::{to_string, output}

///|
pub extend PemError with Eq::{not_equal, equal}

///|
pub extend PemError with Show::{to_string, output}

///|
pub extend PemError with ToJson::{to_json}
