use std::io::Cursor;

use image::{DynamicImage, GrayImage, ImageReader, Limits, imageops};
use qrcode::{Color, EcLevel, QrCode};

use crate::error::{Error, Result};

const MAX_SIDE: u32 = 10_000;
const MAX_ALLOC: u64 = 512 * 1024 * 1024;
const WORK_SIDE: u32 = 1600;

pub struct Matrix {
    pub width: usize,
    pub dark: Vec<bool>,
}

impl Matrix {
    pub fn is_dark(&self, x: usize, y: usize) -> bool {
        self.dark[y * self.width + x]
    }
}

pub fn encode(text: &str) -> Result<Matrix> {
    let code = QrCode::with_error_correction_level(text.as_bytes(), EcLevel::M)
        .map_err(|_| Error::QrTooLarge)?;
    Ok(Matrix {
        width: code.width(),
        dark: code
            .to_colors()
            .into_iter()
            .map(|c| c == Color::Dark)
            .collect(),
    })
}

pub fn decode_file_bytes(bytes: &[u8]) -> Result<Vec<String>> {
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_SIDE);
    limits.max_image_height = Some(MAX_SIDE);
    limits.max_alloc = Some(MAX_ALLOC);
    let mut reader = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|e| Error::Image(e.to_string()))?;
    reader.limits(limits);
    let image = reader.decode().map_err(|e| Error::Image(e.to_string()))?;
    decode_image(&image)
}

pub fn decode_rgba(width: usize, height: usize, rgba: &[u8]) -> Result<Vec<String>> {
    if width == 0 || height == 0 || width > MAX_SIDE as usize || height > MAX_SIDE as usize {
        return Err(Error::Image("unsupported size".to_owned()));
    }
    let image = image::RgbaImage::from_raw(width as u32, height as u32, rgba.to_vec())
        .ok_or_else(|| Error::Image("bad pixel data".to_owned()))?;
    decode_image(&DynamicImage::ImageRgba8(image))
}

pub fn decode_image(image: &DynamicImage) -> Result<Vec<String>> {
    let mut gray = flatten_to_gray(image);
    let mut found = scan(&gray);
    if found.is_empty() {
        imageops::invert(&mut gray);
        found = scan(&gray);
    }
    if found.is_empty() && gray.width().max(gray.height()) > WORK_SIDE {
        imageops::invert(&mut gray);
        let scale = WORK_SIDE as f32 / gray.width().max(gray.height()) as f32;
        let small = imageops::resize(
            &gray,
            ((gray.width() as f32 * scale) as u32).max(1),
            ((gray.height() as f32 * scale) as u32).max(1),
            imageops::FilterType::Triangle,
        );
        found = scan(&small);
    }
    if found.is_empty() {
        Err(Error::NoQrCode)
    } else {
        Ok(found)
    }
}

fn flatten_to_gray(image: &DynamicImage) -> GrayImage {
    let rgba = image.to_rgba8();
    let mut gray = GrayImage::new(rgba.width(), rgba.height());
    for (src, dst) in rgba.pixels().zip(gray.pixels_mut()) {
        let [r, g, b, a] = src.0;
        let luma = (u32::from(r) * 299 + u32::from(g) * 587 + u32::from(b) * 114) / 1000;
        let alpha = u32::from(a);
        dst.0[0] = ((luma * alpha + 255 * (255 - alpha)) / 255) as u8;
    }
    gray
}

fn scan(gray: &GrayImage) -> Vec<String> {
    let mut prepared = rqrr::PreparedImage::prepare(gray.clone());
    let mut out = Vec::new();
    for grid in prepared.detect_grids() {
        if let Ok((_, text)) = grid.decode()
            && !out.contains(&text)
        {
            out.push(text);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render(text: &str, scale: u32, dark: u8, light: u8) -> GrayImage {
        let matrix = encode(text).unwrap();
        let quiet = 4;
        let side = (matrix.width as u32 + quiet * 2) * scale;
        GrayImage::from_fn(side, side, |x, y| {
            let mx = (x / scale) as i64 - quiet as i64;
            let my = (y / scale) as i64 - quiet as i64;
            let on = mx >= 0
                && my >= 0
                && (mx as usize) < matrix.width
                && (my as usize) < matrix.width
                && matrix.is_dark(mx as usize, my as usize);
            image::Luma([if on { dark } else { light }])
        })
    }

    #[test]
    fn encode_then_decode_round_trip() {
        let text = "otpauth://totp/Meskd:me?secret=JBSWY3DPEHPK3PXP&issuer=Meskd";
        let image = DynamicImage::ImageLuma8(render(text, 6, 0, 255));
        assert_eq!(decode_image(&image).unwrap(), vec![text.to_owned()]);
    }

    #[test]
    fn decodes_inverted_codes() {
        let text = "otpauth://totp/dark?secret=JBSWY3DPEHPK3PXP";
        let image = DynamicImage::ImageLuma8(render(text, 6, 255, 20));
        assert_eq!(decode_image(&image).unwrap(), vec![text.to_owned()]);
    }

    #[test]
    fn decodes_png_bytes_and_rgba() {
        let text = "otpauth://totp/png?secret=JBSWY3DPEHPK3PXP";
        let gray = render(text, 5, 0, 255);
        let mut png = Vec::new();
        DynamicImage::ImageLuma8(gray.clone())
            .write_to(&mut Cursor::new(&mut png), image::ImageFormat::Png)
            .unwrap();
        assert_eq!(decode_file_bytes(&png).unwrap(), vec![text.to_owned()]);
        let rgba = DynamicImage::ImageLuma8(gray).to_rgba8();
        let (w, h) = rgba.dimensions();
        assert_eq!(
            decode_rgba(w as usize, h as usize, rgba.as_raw()).unwrap(),
            vec![text.to_owned()]
        );
    }

    #[test]
    fn transparent_background_reads_as_white() {
        let text = "otpauth://totp/alpha?secret=JBSWY3DPEHPK3PXP";
        let gray = render(text, 5, 0, 255);
        let rgba = image::RgbaImage::from_fn(gray.width(), gray.height(), |x, y| {
            if gray.get_pixel(x, y).0[0] == 0 {
                image::Rgba([0, 0, 0, 255])
            } else {
                image::Rgba([0, 0, 0, 0])
            }
        });
        let found = decode_image(&DynamicImage::ImageRgba8(rgba)).unwrap();
        assert_eq!(found, vec![text.to_owned()]);
    }

    #[test]
    fn blank_and_broken_images_fail_cleanly() {
        let blank = DynamicImage::ImageLuma8(GrayImage::from_pixel(200, 200, image::Luma([255])));
        assert!(matches!(decode_image(&blank), Err(Error::NoQrCode)));
        assert!(matches!(
            decode_file_bytes(b"not an image"),
            Err(Error::Image(_))
        ));
        assert!(decode_rgba(0, 0, &[]).is_err());
        assert!(decode_rgba(2, 2, &[0; 3]).is_err());
    }
}
