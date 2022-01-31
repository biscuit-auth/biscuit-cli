use std::error::Error;
use std::fmt;
use std::fmt::Display;

#[derive(Debug, Clone)]
pub struct E {
    pub msg: String,
}

impl Display for E {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", &self.msg)
    }
}

impl Error for E {}
