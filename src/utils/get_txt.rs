use crate::prelude::*;
use crate::types::Asset;

pub fn get_txt_from_file(file: &str) -> Result<Vec<String>> {
    let file = Asset::get(file).ok_or_else(|| RbatError::MissingAsset(file.to_string()))?;

    // converts bytes to string
    let content = String::from_utf8(file.data.to_vec())?;

    // inserts string from each line to texts vec
    let mut texts = Vec::new();
    for line in content.lines() {
        texts.extend(line.split_whitespace().map(|text| text.to_string()));
    }
    Ok(texts)
}
