///|
/// PEM (Privacy-Enhanced Mail) encoding and decoding library
/// 
/// This library provides functionality to encode and decode PEM format data,
/// which is commonly used for storing and sending cryptographic keys, certificates,
/// and other data in a text format.

///|
/// Error types for PEM operations
pub(all) enum PemError {
  /// Invalid PEM format - missing begin/end markers
  InvalidFormat(String)
  /// Invalid base64 encoding in PEM data
  InvalidBase64(String)
  /// Mismatched begin/end labels
  MismatchedLabels(String, String)
  /// Empty PEM data
  EmptyData
  /// Invalid character in label
  InvalidLabel(String)
} derive(Eq, ToJson)

///|
/// A PEM block represents a single PEM-encoded data block
pub(all) struct PemBlock {
  /// The label indicating the type of data (e.g., "CERTIFICATE", "PRIVATE KEY")
  label : String
  /// The decoded binary data
  data : Bytes
  /// Optional headers as key-value pairs
  headers : Map[String, String]
} derive(Eq)

///|
pub impl Show for PemError with output(self, logger) {
  match self {
    InvalidFormat(message) => {
      logger.write_string("InvalidFormat(")
      logger.write_object(message)
      logger.write_string(")")
    }
    InvalidBase64(message) => {
      logger.write_string("InvalidBase64(")
      logger.write_object(message)
      logger.write_string(")")
    }
    MismatchedLabels(begin, end) => {
      logger.write_string("MismatchedLabels(")
      logger.write_object(begin)
      logger.write_string(", ")
      logger.write_object(end)
      logger.write_string(")")
    }
    EmptyData => logger.write_string("EmptyData")
    InvalidLabel(label) => {
      logger.write_string("InvalidLabel(")
      logger.write_object(label)
      logger.write_string(")")
    }
  }
}

///|
pub impl Show for PemBlock with output(self, logger) {
  logger.write_string("{label: ")
  logger.write_object(self.label)
  logger.write_string(", data: ")
  logger.write_object(self.data)
  logger.write_string(", headers: ")
  logger.write_object(self.headers)
  logger.write_string("}")
}

///|
/// Create a new PEM block
pub fn PemBlock::new(
  label~ : String,
  data~ : Bytes,
  headers? : Map[String, String] = Map([]),
) -> PemBlock {
  { label, data, headers }
}

///|
/// Base64 encoding table (RFC 4648)
let base64_chars : String = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

///|
/// Base64 decoding table  
let base64_decode_table : FixedArray[Int] = {
  let table : FixedArray[Int] = FixedArray::make(256, -1)
  for i = 0; i < base64_chars.length(); i = i + 1 {
    let char_code : Int = base64_chars.code_unit_at(i).to_int()
    table[char_code] = i
  }
  table[61] = 0 // '=' padding character
  table
}

///|
/// Encode bytes to base64 string
fn encode_base64(data : Bytes) -> String {
  if data.length() == 0 {
    return ""
  }
  let mut result : String = ""
  let len = data.length()
  let mut i = 0
  while i < len {
    let b1 = data[i].to_int()
    let b2 = if i + 1 < len { data[i + 1].to_int() } else { 0 }
    let b3 = if i + 2 < len { data[i + 2].to_int() } else { 0 }
    let combined = (b1 << 16) | (b2 << 8) | b3
    let c1 = base64_chars.code_unit_at((combined >> 18) & 63).to_int()
      |> Int::unsafe_to_char
    let c2 = base64_chars.code_unit_at((combined >> 12) & 63).to_int()
      |> Int::unsafe_to_char
    let c3 = if i + 1 < len {
      base64_chars.code_unit_at((combined >> 6) & 63).to_int()
      |> Int::unsafe_to_char
    } else {
      '='
    }
    let c4 = if i + 2 < len {
      base64_chars.code_unit_at(combined & 63).to_int() |> Int::unsafe_to_char
    } else {
      '='
    }
    result = result + "\{c1}\{c2}\{c3}\{c4}"
    i = i + 3
  }
  result
}

///|
/// Decode base64 string to bytes
fn decode_base64(input : String) -> Result[Bytes, PemError] {
  let cleaned = input
    .replace(old=" ", new="")
    .replace(old="\t", new="")
    .replace(old="\r", new="")
    .replace(old="\n", new="")
  if cleaned.length() % 4 != 0 {
    return Err(PemError::InvalidBase64("Invalid base64 length"))
  }
  let result : Array[Byte] = []
  let mut i = 0
  while i < cleaned.length() {
    let c1 : Int = cleaned.code_unit_at(i).to_int()
    let c2 : Int = cleaned.code_unit_at(i + 1).to_int()
    let c3 : Int = cleaned.code_unit_at(i + 2).to_int()
    let c4 : Int = cleaned.code_unit_at(i + 3).to_int()
    let v1 = base64_decode_table[c1]
    let v2 = base64_decode_table[c2]
    let v3 = base64_decode_table[c3]
    let v4 = base64_decode_table[c4]
    if v1 == -1 || v2 == -1 || (c3 != 61 && v3 == -1) || (c4 != 61 && v4 == -1) {
      return Err(PemError::InvalidBase64("Invalid base64 character"))
    }
    let combined = (v1 << 18) | (v2 << 12) | (v3 << 6) | v4
    result.push(((combined >> 16) & 255) |> Int::to_byte)
    if c3 != 61 {
      result.push(((combined >> 8) & 255) |> Int::to_byte)
    }
    if c4 != 61 {
      result.push((combined & 255) |> Int::to_byte)
    }
    i = i + 4
  }
  Ok(Bytes::from_array(result))
}

///|
/// Encode a PEM block to string format
pub fn encode(block : PemBlock) -> String {
  let mut result = "-----BEGIN \{block.label}-----\n"

  // Add headers if present
  for key, value in block.headers {
    result = result + "\{key}: \{value}\n"
  }
  if block.headers.length() > 0 {
    result = result + "\n"
  }

  // Encode data in base64 with 64-character line wrapping
  let base64_data = encode_base64(block.data)
  let mut i = 0
  while i < base64_data.length() {
    let end = if i + 64 < base64_data.length() {
      i + 64
    } else {
      base64_data.length()
    }
    result = result + base64_data[i:end].to_string() + "\n"
    i = i + 64
  }
  result = result + "-----END \{block.label}-----"
  result
}

///|
/// Helper function to check if string starts with prefix
pub fn string_starts_with(s : String, prefix : String) -> Bool {
  match s.strip_prefix(prefix) {
    Some(_) => true
    None => false
  }
}

///|
/// Helper function to check if string ends with suffix
pub fn string_ends_with(s : String, suffix : String) -> Bool {
  match s.strip_suffix(suffix) {
    Some(_) => true
    None => false
  }
}

///|
/// Helper function to trim whitespace from a string
fn trim_string(s : String) -> String {
  let mut start = 0
  let mut end = s.length()

  // Find first non-whitespace character
  while start < end {
    let ch = s.code_unit_at(start).to_int()
    if ch != 32 && ch != 9 && ch != 10 && ch != 13 { // space, tab, newline, carriage return
      break
    }
    start = start + 1
  }

  // Find last non-whitespace character
  while end > start {
    let ch = s.code_unit_at(end - 1).to_int()
    if ch != 32 && ch != 9 && ch != 10 && ch != 13 {
      break
    }
    end = end - 1
  }
  if start >= end {
    ""
  } else {
    s[start:end].to_string()
  }
}

///|
/// Decode a PEM string to a PEM block
pub fn decode(pem_data : String) -> Result[PemBlock, PemError] {
  let lines = pem_data.split("\n")
    |> Iter::to_array
    |> Array::map(fn(view) { view.to_string() })
  if lines.length() < 2 {
    return Err(PemError::InvalidFormat("PEM data too short"))
  }

  // Find begin marker
  let mut begin_line_idx = -1
  let mut begin_label = ""
  for i = 0; i < lines.length(); i = i + 1 {
    let line = trim_string(lines[i])
    if string_starts_with(line, "-----BEGIN ") &&
      string_ends_with(line, "-----") {
      begin_line_idx = i
      let start_pos = 11 // length of "-----BEGIN "
      let end_pos = line.length() - 5 // remove "-----"
      begin_label = line[start_pos:end_pos].to_string()
      break
    }
  }
  if begin_line_idx == -1 {
    return Err(PemError::InvalidFormat("Missing BEGIN marker"))
  }

  // Find end marker
  let mut end_line_idx = -1
  let mut end_label = ""
  for i = begin_line_idx + 1; i < lines.length(); i = i + 1 {
    let line = trim_string(lines[i])
    if string_starts_with(line, "-----END ") && string_ends_with(line, "-----") {
      end_line_idx = i
      let start_pos = 9 // length of "-----END "
      let end_pos = line.length() - 5 // remove "-----"
      end_label = line[start_pos:end_pos].to_string()
      break
    }
  }
  if end_line_idx == -1 {
    return Err(PemError::InvalidFormat("Missing END marker"))
  }
  if begin_label != end_label {
    return Err(PemError::MismatchedLabels(begin_label, end_label))
  }

  // Parse headers and data
  let headers : Map[String, String] = Map([])
  let mut data_start_idx = begin_line_idx + 1

  // Look for headers
  for i = begin_line_idx + 1; i < end_line_idx; i = i + 1 {
    let line = trim_string(lines[i])
    if line.is_empty() {
      data_start_idx = i + 1
      break
    }
    if line.contains(":") {
      let parts = line.split(":")
        |> Iter::to_array
        |> Array::map(fn(view) { view.to_string() })
      if parts.length() >= 2 {
        let key = trim_string(parts[0])
        let value = trim_string(parts[1])
        headers[key] = value
        data_start_idx = i + 1
      } else {
        data_start_idx = i
        break
      }
    } else {
      data_start_idx = i
      break
    }
  }

  // Collect base64 data
  let mut base64_data = ""
  for i = data_start_idx; i < end_line_idx; i = i + 1 {
    let line = trim_string(lines[i])
    if !line.is_empty() {
      base64_data = base64_data + line
    }
  }
  if base64_data.is_empty() {
    return Err(PemError::EmptyData)
  }

  // Decode base64 data
  match decode_base64(base64_data) {
    Ok(decoded_data) =>
      Ok(PemBlock::new(label=begin_label, data=decoded_data, headers~))
    Err(error) => Err(error)
  }
}

///|
/// Decode multiple PEM blocks from a string
pub fn decode_many(pem_data : String) -> Result[Array[PemBlock], PemError] {
  let lines = pem_data.split("\n")
    |> Iter::to_array
    |> Array::map(fn(view) { view.to_string() })
  let blocks : Array[PemBlock] = []
  let mut current_block_lines : Array[String] = []
  let mut in_block = false
  for line in lines {
    let trimmed = trim_string(line)
    if string_starts_with(trimmed, "-----BEGIN ") {
      if in_block {
        return Err(PemError::InvalidFormat("Nested BEGIN markers"))
      }
      in_block = true
      current_block_lines = [line]
    } else if string_starts_with(trimmed, "-----END ") {
      if !in_block {
        return Err(PemError::InvalidFormat("END marker without BEGIN"))
      }
      current_block_lines.push(line)

      // Decode this block
      let block_data = current_block_lines.join("\n")
      match decode(block_data) {
        Ok(block) => blocks.push(block)
        Err(error) => return Err(error)
      }
      current_block_lines = []
      in_block = false
    } else if in_block {
      current_block_lines.push(line)
    }
  }
  if in_block {
    return Err(PemError::InvalidFormat("Unclosed PEM block"))
  }
  if blocks.is_empty() {
    return Err(PemError::InvalidFormat("No PEM blocks found"))
  }
  Ok(blocks)
}
