

#[macro_use]
extern crate serde_derive;

extern crate serde;
extern crate serde_json;

extern crate crypto;
extern crate rand;

use rand::{OsRng, Rng};
use crypto::scrypt;
use crypto::scrypt::ScryptParams;
use crypto::util::fixed_time_eq;
use crypto::scrypt::scrypt_simple;
use crypto::scrypt::scrypt_check;
use std::time::Instant;
use std::time::Duration;

#[derive(Serialize, Deserialize, Debug, Copy, Clone, PartialEq, Eq)]
struct ScryptParameter {
    log_n: u8,
    r: u32,
    p: u32,
}

impl ScryptParameter{
    fn to_scrypt(&self) -> ScryptParams {
      return ScryptParams::new(self.log_n, self.r, self.p,);
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct UserEntry {
    username : String,
    hash_settings: ScryptParameter,
    scrypt: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct LoginEnty {
    username: String,
    password: String
}

fn printDuration(elapsed: Duration){
    let nanos = elapsed.subsec_nanos() as u64;
    let ms = (1000*1000*1000 * elapsed.as_secs() + nanos)/(1000 * 1000);
    println!("Took {} ms", ms);
}

fn create_user(login: LoginEnty, params: ScryptParameter) -> UserEntry{
    println!("Creating user {}", login.username);
    let now = Instant::now();
    let mut result = scrypt_simple(&login.password, &params.to_scrypt()).unwrap();
    printDuration(now.elapsed());
    return UserEntry{
        username: login.username,
        hash_settings: params,
        scrypt: result
    };
}

fn compare_user(login: LoginEnty, user: UserEntry) -> bool {

    return fixed_time_eq(&*login.username.as_bytes(), &*user.username.as_bytes()) && scrypt_check(&login.password, &user.scrypt).unwrap();
}

fn login(login: LoginEnty, hash_default_params : ScryptParameter) -> bool{

    //TODO fetch from database
    let mut old_hash_params = hash_default_params.clone();
    old_hash_params.log_n-=1;
    let mut user = create_user(login.clone(), old_hash_params);
    //TODO error handling if user does not exists

    println!("Checking login for user {}", login.username);
    let now = Instant::now();
    let equal = compare_user(login.clone(), user.clone());
    printDuration(now.elapsed());

    if(equal){
        println!("User {} logged in", user.username);
        if(user.hash_settings != hash_default_params){
            println!("upgrading user params for user: {}", user.username);
            user = create_user(login, hash_default_params);
            // send user to database
        }
    }

    return equal;
}



fn main() {

    let hash_defaults: ScryptParameter = ScryptParameter{
        log_n: 20,
        r: 8,
        p: 1
    };

    let login_entry = LoginEnty {
        username: "Mimoja".to_string(),
        password: "test1234".to_string(),
    };


    login(login_entry, hash_defaults);

    /*
    let entry = create_user(login, hash_defaults);
    let j = serde_json::to_string(&entry).unwrap();
    println!("{}", j);
    let deserialized: UserEntry = serde_json::from_str(&j).unwrap();
    println!("{:?}", deserialized);
    */
}


