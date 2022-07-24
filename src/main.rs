use clap::Parser;
use cryptoxide::{digest::Digest, sha3::Keccak256};
use hex::encode;
use rand::RngCore;
use regex::Regex;
use secp256k1::{constants::SECRET_KEY_SIZE, PublicKey, Secp256k1, SecretKey};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
  #[clap(short, long, value_parser, default_value = "")]
  start: String,
  #[clap(short, long, value_parser, default_value = "")]
  end: String,
  #[clap(short, long, value_parser, default_value = "4")]
  threads: i8,
}

fn gen_pair(engine: &Secp256k1<secp256k1::All>) -> (String, String) {
  let mut hasher = Keccak256::new();
  let mut rng = rand::thread_rng();
  let mut pri_slice = [0u8; SECRET_KEY_SIZE];
  let mut digest = [0u8; SECRET_KEY_SIZE];
  rng.fill_bytes(&mut pri_slice);
  let prikey = SecretKey::from_slice(&pri_slice).unwrap();
  let input = &PublicKey::from_secret_key(&engine, &prikey).serialize_uncompressed()[1..];
  hasher.input(input);
  hasher.result(&mut digest);
  (encode(&pri_slice), encode(&digest[digest.len() - 20..]))
}

fn handling(re: Arc<Regex>) {
  static COUNT: AtomicUsize = AtomicUsize::new(0);
  static IS_DONE: AtomicUsize = AtomicUsize::new(0);
  let engine = Secp256k1::new();
  loop {
    if IS_DONE.load(Ordering::Relaxed) == 1 {
      break;
    }
    print!("\r{:?}", COUNT);
    let (prikey, addr) = gen_pair(&engine);
    if re.is_match(&addr[..]) {
      println!("\nprikey: {:?}", &prikey);
      println!("address: {:?}", &addr);
      IS_DONE.store(1, Ordering::Relaxed);
      break;
    }
    COUNT.fetch_add(1, Ordering::SeqCst);
  }
}

// fn exp(t_num: i8) {
//   static COUNT: AtomicUsize = AtomicUsize::new(0);
//   for number in 0..10 {
//     println!("[{}] exp on count: {:?} {} times", t_num, COUNT, number);
//     COUNT.fetch_add(1, Ordering::SeqCst);
//   }
// }

fn main() {
  let args = Cli::parse();
  // need checking on inputs
  let mut re_str = String::from("^(");
  re_str.push_str(&args.start);
  re_str.push_str(").+(");
  re_str.push_str(&args.end);
  re_str.push_str(")$");
  let _re = Regex::new(
    &re_str,
    // "^(000|0a0|111|1ce|888|8a8|bad|bed|bee|ace|dad|ca7|d09).+(900d|1dea|f001|babe|fade|face|cafe)$",
    // "^(000|0a0|111|1ce|888|8a8|bad|bed|bee|ace|dad|ca7|d09)",
  )
  .unwrap();
  let re = Arc::new(_re);
  let mut threads = Vec::new();
  println!("Checking address...");
  for _ in 0..args.threads {
    let re = Arc::clone(&re);
    let t = thread::spawn(move || handling(re));
    threads.push(t);
  }
  for t in threads {
    t.join().unwrap();
  }
}
