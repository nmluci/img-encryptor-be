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

static MAGIC_STRING: [u8; 8] = [0x4e, 0x2d, 0x51, 0xfa, 0x30, 0x57, 0x30, 0x5f];

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

      #[arg(short, long)]
      thumbnail: Option<PathBuf>,
   },
   Decrypt {
      #[arg(short, long)]
      filepath: PathBuf,

      #[arg(short, long)]
      key: String,

      #[arg(short, long)]
      output: Option<PathBuf>,
   },
}

fn encrypt_file(
   filepath: &PathBuf,
   thumbnail: &Option<PathBuf>,
   outpath: &Option<PathBuf>,
   key: &Option<String>,
) {
   let raw_img = fs::read(filepath).expect("failed to open raw img");

   let out = if let Some(v) = outpath {
      v.clone()
   } else {
      let mut temp = filepath.clone();
      temp.set_extension(format!(
         "enc.{}",
         temp.extension().unwrap_or_default().to_str().unwrap()
      ));
      temp
   };

   let file = fs::OpenOptions::new()
      .create(true)
      .write(true)
      .append(true)
      .open(out)
      .expect("failed to create filestream");
   let mut buf = BufWriter::new(file);

   if let Some(tb) = thumbnail {
      let raw_timg = fs::read(tb).expect("failed to load thumbnails");
      
      let img = image::load_from_memory(&raw_timg).expect("failed to parse img");
      let img_ext = image::guess_format(&raw_timg).expect("failed to guess img format");

      img.write_to(&mut buf, img_ext).expect("failed to write baseimg");
   } else {
      let raw_timg = fs::read(filepath).expect("failed to load thumbnails");

      let img = image::load_from_memory(&raw_timg).expect("failed to parse img");
      let img_ext = image::guess_format(&raw_timg).expect("failed to guess img format");

      let resized = img.resize(
         img.width() / 20,
         img.height() / 20,
         image::imageops::FilterType::Gaussian,
      );
      let blurred = resized.blur(0.6);
      blurred
         .write_to(&mut buf, img_ext)
         .expect("failed to write baseimg");
   };

   let mut iv = [0u8; 16];
   OsRng.fill_bytes(&mut iv);

   let secret: GenericArray<u8, U32> = if let Some(v) = key {
      GenericArray::clone_from_slice(&BASE64.decode(v.as_bytes()).expect("failed to decode key"))
   } else {
      let mut temp = [0u8; 32];
      OsRng.fill_bytes(&mut temp);

      println!("key used: {}", BASE64.encode(&temp.clone()));

      GenericArray::clone_from_slice(&temp)
   };

   let enc_img = security::aes256_encrypt(secret, iv, &raw_img);
   buf.write_all(&MAGIC_STRING)
      .expect("failed to write separator");
   buf.write_all(&iv).expect("failed to write iv");
   buf.write_all(&enc_img).expect("failed to write enc img");
   buf.flush().expect("failed to flush buffer");
}

fn decrypt_file(filepath: &PathBuf, outpath: &Option<PathBuf>, key: &String) {
   let rawdata = fs::read(filepath).expect("failed to open raw data");

   let sep_idx = rawdata
      .windows(MAGIC_STRING.len())
      .position(|v| v == MAGIC_STRING)
      .expect("magic number not found");

   // returned [thumbnails, padded_enc_img]
   let (_, padded_enc_img) = rawdata.split_at(sep_idx);
   // returned [magic_number, iv+enc_img]
   let (_, sec_img) = padded_enc_img.split_at(8);
   // returned [iv, enc_img]
   let (raw_iv, enc_img) = sec_img.split_at(16);

   let mut iv = [0u8; 16];
   iv.clone_from_slice(raw_iv);

   let secret: GenericArray<u8, U32> =
      GenericArray::clone_from_slice(&BASE64.decode(key.as_bytes()).expect("failed to decode key"));

   let img_data = security::aes256_decrypt(secret, iv, enc_img).expect("failed to decrypt img");
   let img = image::load_from_memory(&img_data).expect("failed to load img");
   let img_ext = image::guess_format(&img_data).expect("failed to guess img");

   let out = if let Some(v) = outpath {
      v.clone()
   } else {
      let filestem = filepath.file_stem().unwrap_or_default().to_string_lossy();
      let mut temp = filepath.clone();

      println!("{}", filestem);

      if filestem.contains("enc") {
         let new_filename: Vec<&str> = filestem.split(".enc").collect();
         temp.set_file_name(new_filename.join(""));
         temp.set_extension(filepath.extension().unwrap());

         temp
      } else {
         let file_stem = filepath.file_stem().unwrap_or_default();
         temp.set_file_name(OsStr::new(
            format!("{}_dec", file_stem.to_str().unwrap()).as_str(),
         ));
         temp
      }
   };

   img.save_with_format(out, img_ext)
      .expect("failed to save img");
}

fn main() {
   let cli = Cli::parse();

   match &cli.mode {
      Some(Modes::Encrypt {
         filepath,
         key,
         output,
         thumbnail,
      }) => encrypt_file(filepath, thumbnail, output, key),
      Some(Modes::Decrypt {
         filepath,
         key,
         output,
      }) => decrypt_file(filepath, output, key),
      None => todo!(),
   }
}
