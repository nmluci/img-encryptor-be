use aes::cipher::generic_array::GenericArray;
use aes::cipher::typenum::U32;
use clap::{Parser, Subcommand};
use corelib::security::{self, expand_secret_key};
use data_encoding::BASE64;
use image::{DynamicImage, GenericImageView, ImageBuffer, ImageFormat, Rgba, RgbaImage};
use rand_core::{OsRng, RngCore};
use std::ffi::OsStr;
use std::fs;
use std::io::{BufWriter, Cursor, Write};
use std::path::PathBuf;
use rayon::prelude::*;

static MAGIC_STRING: [u8; 8] = [0x4e, 0x2d, 0x51, 0xfa, 0x30, 0x57, 0x30, 0x5f];
static PAT_START_MAGIC_STRING: [u8; 6] = [0x0a, 0x0a, 0x00, 0x00, 0x0a, 0x0a];
static PAT_END_MAGIC_STRING: [u8; 6] = [0x0a, 0x0a, 0xff, 0xff, 0x0a, 0x0a];
static APAT_START_MAGIC_STRING: [u8; 6] = [0x0a, 0x0b, 0x00, 0x00, 0x0a, 0x0b];
static APAT_END_MAGIC_STRING: [u8; 6] = [0x0a, 0x0b, 0xff, 0xff, 0x0a, 0x0b];

#[derive(Parser)]
#[command(author, version, about, long_about=None)]
struct Cli {
	#[command(subcommand)]
	mode: Option<Modes>,
}

#[derive(Subcommand)]
enum Modes {
	Encrypt {
		#[arg(short, long, action = clap::ArgAction::Append)]
		filepath: Vec<PathBuf>,
		
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

fn parse_img_format(n: u8) -> ImageFormat {
	match n {
		1 => ImageFormat::Jpeg,
		2 => ImageFormat::Gif,
		3 => ImageFormat::WebP,
		5 => ImageFormat::Tiff,
		6 => ImageFormat::Tga,
		8 => ImageFormat::Bmp,
		9 => ImageFormat::Ico,
		10 => ImageFormat::Hdr,
		_ => ImageFormat::Png,
	}
}

fn combine_image(pat_img: DynamicImage, apat_img: DynamicImage) -> ImageBuffer<Rgba<u8>, Vec<u8>> {
	if pat_img.dimensions() != apat_img.dimensions() {
		panic!("bruh")
	};
	
	let (width, height) = pat_img.dimensions();
	let mut og_img = RgbaImage::new(width, height);
	
	for y in 0..height {
		for x in 0..width {
			let pat_pxl = pat_img.get_pixel(x, y);
			let apat_pxl = apat_img.get_pixel(x, y);
			
			let og_img_pxl = Rgba([
				pat_pxl[0] | apat_pxl[0],
				pat_pxl[1] | apat_pxl[1],
				pat_pxl[2] | apat_pxl[2],
				255],
			);
			
			og_img.put_pixel(x, y, og_img_pxl);
		}
	}
	
	og_img
}

fn split_image(filename: &str, og_img: DynamicImage) -> (Vec<u8>, Vec<u8>) {
	let (width, height) = og_img.dimensions();
	let mut pat_img = RgbaImage::new(width, height);
	let mut apat_img = RgbaImage::new(width, height);
	
	let checkboard = |x: u32, y: u32| (x.wrapping_mul(y) / 16).count_ones() % 2 == 0;
	
	for y in 0..height {
		for x in 0..width {
			let pxl = og_img.get_pixel(x, y);
			
			if checkboard(x, y) {
				pat_img.put_pixel(x, y, pxl);
			} else {
				apat_img.put_pixel(x, y, pxl);
			}
		}
	}
	
	pat_img
	.save(format!("a_{}", filename))
	.expect("failed to save temp file a");
	apat_img
	.save(format!("b_{}", filename))
	.expect("failed to save temp file b");
	
	let mut pat_vec = Vec::new();
	let mut pat_cursor = Cursor::new(&mut pat_vec);
	
	let mut apat_vec = Vec::new();
	let mut apat_cursor = Cursor::new(&mut apat_vec);
	
	pat_img
	.write_to(&mut pat_cursor, ImageFormat::Jpeg)
	.expect("failed to write pattern img");
	apat_img
	.write_to(&mut apat_cursor, ImageFormat::Jpeg)
	.expect("failed to write anti-pattern img");
	
	(pat_vec, apat_vec)
}

fn encrypt_data(
	filepath: &PathBuf,
	thumbnail: &Option<PathBuf>,
	outpath: &Option<PathBuf>,
	key: &Option<String>,
) {
	let raw_img = fs::read(filepath).expect("failed to open raw img");
	let og_img = image::load_from_memory(&raw_img).expect("failed to parse img");
	let og_ext = image::guess_format(&raw_img).expect("failed to guess img format");
	let og_filename = filepath.file_name().unwrap().to_str().unwrap();

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
		
		img.write_to(&mut buf, img_ext)
		.expect("failed to write baseimg");
	} else {
		let raw_timg = fs::read(filepath).expect("failed to load thumbnails");
		
		let img = image::load_from_memory(&raw_timg).expect("failed to parse img");
		let img_ext = image::guess_format(&raw_timg).expect("failed to guess img format");
		
		let resized = img.resize(
			img.width(),
			img.height(),
			image::imageops::FilterType::Gaussian,
		);
		let blurred = resized.blur(0.6);
		blurred
		.write_to(&mut buf, img_ext)
		.expect("failed to write baseimg");
	};
	
	let mut iv = [0u8; 16];
	OsRng.fill_bytes(&mut iv);
	
	let (pat_key, apat_key): (GenericArray<u8, U32>, GenericArray<u8, U32>) = if let Some(v) = key {
		let secret = BASE64.decode(v.as_bytes()).expect("failed to decode key");
		
		expand_secret_key(secret).expect("failed to expand key")
	} else {
		let mut temp = [0u8; 32];
		OsRng.fill_bytes(&mut temp);
		
		println!("filename: {} key used: {}", og_filename, BASE64.encode(&temp.clone()));
		
		expand_secret_key(temp.to_vec()).expect("failed to expand key")
	};
	
	let (pattern_img, antipattern_img) = split_image(og_filename, og_img);
	
	let enc_pattern_img = security::aes256_encrypt(pat_key, &pattern_img);
	let enc_antipattern_img = security::aes256_encrypt(apat_key, &antipattern_img);
	
	fs::write("enc_pat_img", enc_pattern_img.clone());
	fs::write("enc_apat_img", enc_antipattern_img.clone());
	fs::write("pat_img", pattern_img);
	fs::write("apat_img", antipattern_img);


	buf.write_all(&MAGIC_STRING)
	.expect("failed to write separator");
	buf.write_all(&[og_ext as u8])
	.expect("failed to write img type");
	
	buf.write_all(&PAT_START_MAGIC_STRING)
	.expect("failed to write pattern-start magicstr");
	buf.write_all(&enc_pattern_img)
	.expect("failed to write pattern data");
	buf.write_all(&PAT_END_MAGIC_STRING)
	.expect("failed to write pattern-end magicstr");
	
	buf.write_all(&APAT_START_MAGIC_STRING)
	.expect("failed to write apattern-start magicstr");
	buf.write_all(&enc_antipattern_img)
	.expect("failed to write apattern data");
	buf.write_all(&APAT_END_MAGIC_STRING)
	.expect("failed to write apattern-end magicstr");
	
	buf.flush().expect("failed to flush buffer");
}

fn decrypt_data(filepath: &PathBuf, outpath: &Option<PathBuf>, key: &String) {
	let rawdata = fs::read(filepath).expect("failed to open raw data");
	
	let enc_sep_idx = rawdata
	.windows(MAGIC_STRING.len())
	.position(|v| v == MAGIC_STRING)
	.expect("magic number not found");
	
	// returned [thumbnails, padded_enc_img]
	let (_, padded_enc_img) = rawdata.split_at(enc_sep_idx);
	
	// returned [magic_number, iv+enc_img]
	let (header, sec_img) = padded_enc_img.split_at(9);
	
	let img_type = parse_img_format(header[header.len() - 1]);
	let apat_sep_idx = sec_img
	.windows(APAT_START_MAGIC_STRING.len())
	.position(|v| v == APAT_START_MAGIC_STRING)
	.expect("magic number not found");
	
	// [pattern, anti-pattern]
	let (pat, apat) = sec_img.split_at(apat_sep_idx);
	
	let (_, pat_mid) = pat.split_at(6);
	let (pat_data, _) = pat_mid.split_at(pat_mid.len() - 6);
	
	let (_, apat_mid) = apat.split_at(6);
	let (apat_data, _) = apat_mid.split_at(apat_mid.len() - 6);
	
	let (pat_key, apat_key): (GenericArray<u8, U32>, GenericArray<u8, U32>) = {
		let secret = BASE64.decode(key.as_bytes()).expect("failed to decode key");
		
		expand_secret_key(secret).expect("failed to expand key")
	};
	
	let pat_img =
	security::aes256_decrypt(pat_key, pat_data).expect("failed to decrypt pattern img");
	let pat_img = image::load_from_memory_with_format(&pat_img, ImageFormat::Jpeg)
	.expect("failed to load pattern img");
	// let pat_img = image::load_from_memory(&pat_img).expect("failed to load pattern img");
	
	let apat_img =
	security::aes256_decrypt(apat_key, apat_data).expect("failed to decrypt anti-pattern img");
	let apat_img = image::load_from_memory_with_format(&apat_img, ImageFormat::Jpeg)
	.expect("failed to load anti-pattern img");
	
	let actual_data = combine_image(pat_img, apat_img);
	
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
	
	actual_data
	.save_with_format(out, img_type)
	.expect("failed to save img");
}

fn encrypt_multidata(filepath: &Vec<PathBuf>, thumbnail: &Option<PathBuf>, outpath: &Option<PathBuf>,key: &Option<String>) {
	if filepath.len() == 1 {
		return encrypt_data(&filepath[0], thumbnail, outpath, key);
	}
	
	filepath.into_par_iter().for_each(|path| {
		encrypt_data(path, thumbnail, &None, &None);
	});
}

fn main() {
	let cli = Cli::parse();
	
	match &cli.mode {
		Some(Modes::Encrypt {
			filepath,
			key,
			output,
			thumbnail,
		}) => encrypt_multidata(filepath, thumbnail, output, key),
		Some(Modes::Decrypt {
			filepath,
			key,
			output,
		}) => decrypt_data(filepath, output, key),
		None => todo!(),
	}
}
