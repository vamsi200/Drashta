// #![allow(unused_imports)]
// use anyhow::Result;
// use log::info;
// use sled::Db;
// use uuid::Uuid;
//
// pub fn insert_into_db(data: String, get_data: bool) -> Result<()> {
//     let db: sled::Db = sled::open("test_db")?;
//     let key = Uuid::new_v4();
//     let value = data;
//     if let Ok(_) = db.insert(key, value.as_bytes()) {
//         info!("Data inserted into DB");
//     }
//
//     if get_data {
//         info!("Getting Data..");
//         get_data_from_db(db, key)?;
//     }
//     Ok(())
// }
//
// pub fn get_data_from_db(db: Db, id: Uuid) -> Result<()> {
//     if let Some(val) = db.get(&id)? {
//         let json_str = String::from_utf8(val.to_vec()).unwrap();
//         println!("{}", json_str);
//     }
//     Ok(())
// }
