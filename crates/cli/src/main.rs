use aes::cipher::generic_array::GenericArray;
use aes::cipher::typenum::U32;
use clap::{Parser, Subcommand};
use corelib::security;
use data_encoding::BASE64;
use rand_core::{OsRng, RngCore};
use std::ffi::OsStr;
use std::fs;
use std::io::{BufWriter, Write};
use std::path::PathBuf;

#[derive(Parser)]
#[command(author, version, about, long_about=None)]
struct Cli {
   #[command(subcommand)]
   mode: Option<Modes>,
}

#[derive(Subcommand)]
enum Modes {
   Encrypt {
      #[arg(short, long)]
      filepath: PathBuf,

      #[arg(short, long)]
      key: Option<String>,

      #[arg(short, long)]
      output: Option<PathBuf>,
   },
   Decrypt {
      #[arg(short, long)]
      filepath: PathBuf,

      #[arg(short, long, default_value = "")]
      key: String,

      #[arg(short, long)]
      output: Option<PathBuf>,
   },
}

fn encrypt_file(filepath: &PathBuf, outpath: &Option<PathBuf>, key: &Option<String>) {
   let raw_img = fs::read(filepath).expect("failed to open raw img");
   let img_ext = image::guess_format(&raw_img).expect("failed to guess img format");

   let img = image::load_from_memory(&raw_img).expect("failed to parse img");
   let imgdata = img.as_bytes();

   let out = if let Some(v) = outpath {
      v.clone()
   } else {
      let mut temp = filepath.clone();
      temp.set_extension(
         [
            OsStr::new("enc"),
            temp.extension().unwrap_or(OsStr::new("")),
         ]
         .join(OsStr::new(".")),
      );

      temp
   };

   let file = fs::OpenOptions::new()
               .create(true)
               .write(true)
               .append(true)
               .open(out)
               .expect("failed to create filestream");
   let mut buf = BufWriter::new(file);

   let resized = img.resize(
      img.width() / 20,
      img.height() / 20,
      image::imageops::FilterType::Gaussian,
   );
   let blurred = resized.blur(0.6);
   blurred.write_to(&mut buf, img_ext).expect("failed to write baseimg");

   let mut iv = [0u8; 16];
   OsRng.fill_bytes(&mut iv);

   let secret: GenericArray<u8, U32> = if let Some(v) = key {
      GenericArray::clone_from_slice(&BASE64.decode(v.as_bytes()).expect("failed to decode file"))
   } else {
      let mut temp = [0u8; 32];
      OsRng.fill_bytes(&mut temp);

      println!("key used: {}", BASE64.encode(&temp.clone()));

      GenericArray::clone_from_slice(&temp)
   };

   let enc_img = security::aes256_encrypt(secret, iv, imgdata);
   buf.write_all(&enc_img).expect("failed to write enc img");
   buf.flush().expect("failed to flush buffer");
}

fn decrypt_file(filepath: &PathBuf, outpath: &Option<PathBuf>, key: &String) {
   todo!()
}

fn main() {
   let cli = Cli::parse();

   match &cli.mode {
      Some(Modes::Encrypt {
         filepath,
         key,
         output,
      }) => encrypt_file(filepath, output, key),
      Some(Modes::Decrypt {
         filepath,
         key,
         output,
      }) => decrypt_file(filepath, output, key),
      None => todo!(),
   }
}
