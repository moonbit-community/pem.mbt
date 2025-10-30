///|
/// Tests for PEM encoding and decoding functionality

/// Helper function to check if string starts with prefix (for tests)
fn string_starts_with(s : String, prefix : String) -> Bool {
  match s.strip_prefix(prefix) {
    Some(_) => true
    None => false
  }
}

/// Helper function to check if string ends with suffix (for tests)
fn string_ends_with(s : String, suffix : String) -> Bool {
  match s.strip_suffix(suffix) {
    Some(_) => true
    None => false
  }
}

test "encode_simple_pem_block" {
  let data = b"Hello, World!"
  let block = @pem.PemBlock::new(label="MESSAGE", data~)
  let encoded = @pem.encode(block)
  inspect(
    encoded,
    content=(
      #|-----BEGIN MESSAGE-----
      #|SGVsbG8sIFdvcmxkIQ==
      #|-----END MESSAGE-----
    ),
  )
}

///|
test "encode_pem_block_with_headers" {
  let data = b"Test data"
  let headers : Map[String, String] = { "Version": "1.0", "Algorithm": "RSA" }
  let block = @pem.PemBlock::new(label="CERTIFICATE", data~, headers~)
  let encoded = @pem.encode(block)
  inspect(
    encoded,
    content=(
      #|-----BEGIN CERTIFICATE-----
      #|Version: 1.0
      #|Algorithm: RSA
      #|
      #|VGVzdCBkYXRh
      #|-----END CERTIFICATE-----
    ),
  )
}

///|
test "encode_empty_data" {
  let data = b""
  let block = @pem.PemBlock::new(label="EMPTY", data~)
  let encoded = @pem.encode(block)
  inspect(
    encoded,
    content=(
      #|-----BEGIN EMPTY-----
      #|-----END EMPTY-----
    ),
  )
}

///|
test "encode_long_data_with_line_wrapping" {
  // Create data that will require line wrapping (more than 64 base64 chars)
  let long_data = Bytes::from_array(Array::make(100, 65)) // 100 'A' characters
  let block = @pem.PemBlock::new(label="LONG DATA", data=long_data)
  let encoded = @pem.encode(block)

  // Verify it contains line breaks and proper structure
  let lines = encoded.split("\n") |> Iter::to_array
  inspect(lines.length() > 3, content="true") // Should have multiple lines
  inspect(lines[0].to_string(), content="-----BEGIN LONG DATA-----")
  inspect(
    lines[lines.length() - 1].to_string(),
    content="-----END LONG DATA-----",
  )
}

///|
test "decode_simple_pem_block" {
  let pem_data =
    #|-----BEGIN MESSAGE-----
    #|SGVsbG8sIFdvcmxkIQ==
    #|-----END MESSAGE-----
  let result = @pem.decode(pem_data)
  match result {
    Ok(block) => {
      inspect(block.label, content="MESSAGE")
      inspect(
        block.data.to_string(),
        content=(
          #|b"Hello, World!"
        ),
      )
      inspect(block.headers.length(), content="0")
    }
    Err(error) => fail("Unexpected error: \{error}")
  }
}

///|
test "decode_pem_block_with_headers" {
  let pem_data =
    #|-----BEGIN CERTIFICATE-----
    #|Version: 1.0
    #|Algorithm: RSA
    #|
    #|VGVzdCBkYXRh
    #|-----END CERTIFICATE-----
  let result = @pem.decode(pem_data)
  match result {
    Ok(block) => {
      inspect(block.label, content="CERTIFICATE")
      inspect(
        block.data.to_string(),
        content=(
          #|b"Test data"
        ),
      )
      inspect(block.headers.length(), content="2")
      inspect(
        block.headers.get("Version"),
        content=(
          #|Some("1.0")
        ),
      )
      inspect(
        block.headers.get("Algorithm"),
        content=(
          #|Some("RSA")
        ),
      )
    }
    Err(error) => fail("Unexpected error: \{error}")
  }
}

///|
test "decode_multiline_base64" {
  let pem_data =
    #|-----BEGIN DATA-----
    #|VGhpcyBpcyBhIGxvbmcgbGluZSBvZiBkYXRhIHRoYXQgd2lsbCBiZSBz
    #|cGxpdCBhY3Jvc3MgbXVsdGlwbGUgbGluZXMgaW4gdGhlIFBFTSBmb3Jt
    #|YXQ=
    #|-----END DATA-----
  let result = @pem.decode(pem_data)
  match result {
    Ok(block) => {
      inspect(block.label, content="DATA")
      inspect(
        block.data.to_string(),
        content=(
          #|b"This is a long line of data that will be split across multiple lines in the PEM format"
        ),
      )
    }
    Err(error) => fail("Unexpected error: \{error}")
  }
}

///|
test "decode_pem_with_whitespace" {
  let pem_data =
    #|  -----BEGIN MESSAGE-----  
    #|  SGVsbG8sIFdvcmxkIQ==  
    #|  -----END MESSAGE-----  
  let result = @pem.decode(pem_data)
  match result {
    Ok(block) => {
      inspect(block.label, content="MESSAGE")
      inspect(
        block.data.to_string(),
        content=(
          #|b"Hello, World!"
        ),
      )
    }
    Err(error) => fail("Unexpected error: \{error}")
  }
}

///|
test "roundtrip_encoding_decoding" {
  let original_data = b"This is a test message for roundtrip encoding/decoding"
  let headers : Map[String, String] = { "Test": "true", "Version": "2.0" }
  let original_block = @pem.PemBlock::new(
    label="TEST",
    data=original_data,
    headers~,
  )
  let encoded = @pem.encode(original_block)
  let decoded_result = @pem.decode(encoded)
  match decoded_result {
    Ok(decoded_block) => {
      inspect(decoded_block.label, content="TEST")
      inspect(decoded_block.data.to_string(), content=original_data.to_string())
      inspect(
        decoded_block.headers.get("Test"),
        content=(
          #|Some("true")
        ),
      )
      inspect(
        decoded_block.headers.get("Version"),
        content=(
          #|Some("2.0")
        ),
      )
    }
    Err(error) => fail("Roundtrip failed: \{error}")
  }
}

///|
test "decode_multiple_pem_blocks" {
  let pem_data =
    #|-----BEGIN FIRST-----
    #|Zmlyc3Q=
    #|-----END FIRST-----
    #|-----BEGIN SECOND-----
    #|c2Vjb25k
    #|-----END SECOND-----
    #|-----BEGIN THIRD-----
    #|dGhpcmQ=
    #|-----END THIRD-----
  let result = @pem.decode_many(pem_data)
  match result {
    Ok(blocks) => {
      inspect(blocks.length(), content="3")
      inspect(blocks[0].label, content="FIRST")
      inspect(
        blocks[0].data.to_string(),
        content=(
          #|b"first"
        ),
      )
      inspect(blocks[1].label, content="SECOND")
      inspect(
        blocks[1].data.to_string(),
        content=(
          #|b"second"
        ),
      )
      inspect(blocks[2].label, content="THIRD")
      inspect(
        blocks[2].data.to_string(),
        content=(
          #|b"third"
        ),
      )
    }
    Err(error) => fail("Unexpected error: \{error}")
  }
}

///|
test "decode_error_missing_begin" {
  let pem_data =
    #|SGVsbG8sIFdvcmxkIQ==
    #|-----END MESSAGE-----
  let result = @pem.decode(pem_data)
  match result {
    Err(@pem.PemError::InvalidFormat(msg)) =>
      inspect(msg, content="Missing BEGIN marker")
    Ok(_) => fail("Expected error for missing BEGIN marker")
    Err(other) => fail("Unexpected error type: \{other}")
  }
}

///|
test "decode_error_missing_end" {
  let pem_data =
    #|-----BEGIN MESSAGE-----
    #|SGVsbG8sIFdvcmxkIQ==
  let result = @pem.decode(pem_data)
  match result {
    Err(@pem.PemError::InvalidFormat(msg)) =>
      inspect(msg, content="Missing END marker")
    Ok(_) => fail("Expected error for missing END marker")
    Err(other) => fail("Unexpected error type: \{other}")
  }
}

///|
test "decode_error_mismatched_labels" {
  let pem_data =
    #|-----BEGIN MESSAGE-----
    #|SGVsbG8sIFdvcmxkIQ==
    #|-----END CERTIFICATE-----
  let result = @pem.decode(pem_data)
  match result {
    Err(@pem.PemError::MismatchedLabels(begin, end)) => {
      inspect(begin, content="MESSAGE")
      inspect(end, content="CERTIFICATE")
    }
    Ok(_) => fail("Expected error for mismatched labels")
    Err(other) => fail("Unexpected error type: \{other}")
  }
}

///|
test "decode_error_empty_data" {
  let pem_data =
    #|-----BEGIN MESSAGE-----
    #|-----END MESSAGE-----
  let result = @pem.decode(pem_data)
  match result {
    Err(@pem.PemError::EmptyData) =>
      // Expected
      ()
    Ok(_) => fail("Expected error for empty data")
    Err(other) => fail("Unexpected error type: \{other}")
  }
}

///|
test "decode_error_invalid_base64" {
  let pem_data =
    #|-----BEGIN MESSAGE-----
    #|Invalid@Base64!
    #|-----END MESSAGE-----
  let result = @pem.decode(pem_data)
  match result {
    Err(@pem.PemError::InvalidBase64(_)) =>
      // Expected
      ()
    Ok(_) => fail("Expected error for invalid base64")
    Err(other) => fail("Unexpected error type: \{other}")
  }
}

///|
test "decode_error_too_short" {
  let pem_data = "short"
  let result = @pem.decode(pem_data)
  match result {
    Err(@pem.PemError::InvalidFormat(msg)) =>
      inspect(msg, content="PEM data too short")
    Ok(_) => fail("Expected error for too short data")
    Err(other) => fail("Unexpected error type: \{other}")
  }
}

///|
test "decode_many_error_nested_begin" {
  let pem_data =
    #|-----BEGIN FIRST-----
    #|-----BEGIN SECOND-----
    #|-----END SECOND-----
    #|-----END FIRST-----
  let result = @pem.decode_many(pem_data)
  match result {
    Err(@pem.PemError::InvalidFormat(msg)) =>
      inspect(msg, content="Nested BEGIN markers")
    Ok(_) => fail("Expected error for nested BEGIN markers")
    Err(other) => fail("Unexpected error type: \{other}")
  }
}

///|
test "decode_many_error_end_without_begin" {
  let pem_data =
    #|-----END MESSAGE-----
    #|SGVsbG8=
  let result = @pem.decode_many(pem_data)
  match result {
    Err(@pem.PemError::InvalidFormat(msg)) =>
      inspect(msg, content="END marker without BEGIN")
    Ok(_) => fail("Expected error for END without BEGIN")
    Err(other) => fail("Unexpected error type: \{other}")
  }
}

///|
test "decode_many_error_unclosed_block" {
  let pem_data =
    #|-----BEGIN MESSAGE-----
    #|SGVsbG8=
  let result = @pem.decode_many(pem_data)
  match result {
    Err(@pem.PemError::InvalidFormat(msg)) =>
      inspect(msg, content="Unclosed PEM block")
    Ok(_) => fail("Expected error for unclosed block")
    Err(other) => fail("Unexpected error type: \{other}")
  }
}

///|
test "decode_many_error_no_blocks" {
  let pem_data = "No PEM blocks here\nJust plain text"
  let result = @pem.decode_many(pem_data)
  match result {
    Err(@pem.PemError::InvalidFormat(msg)) =>
      inspect(msg, content="No PEM blocks found")
    Ok(_) => fail("Expected error for no blocks")
    Err(other) => fail("Unexpected error type: \{other}")
  }
}

///|
test "pem_block_constructor" {
  let data = b"test data"
  let headers : Map[String, String] = { "key": "value" }
  let block = @pem.PemBlock::new(label="TEST", data~, headers~)
  inspect(block.label, content="TEST")
  inspect(
    block.data.to_string(),
    content=(
      #|b"test data"
    ),
  )
  inspect(
    block.headers.get("key"),
    content=(
      #|Some("value")
    ),
  )
}

///|
test "pem_block_constructor_default_headers" {
  let data = b"test data"
  let block = @pem.PemBlock::new(label="TEST", data~)
  inspect(block.label, content="TEST")
  inspect(
    block.data.to_string(),
    content=(
      #|b"test data"
    ),
  )
  inspect(block.headers.length(), content="0")
}

///|
/// Documentation Examples
/// These tests serve as comprehensive usage examples
test "documentation_basic_encoding" {
  // Basic encoding example
  let data = b"Hello, World!"
  let block = PemBlock::new(label="MESSAGE", data~)
  let encoded = encode(block)
  inspect(
    string_starts_with(encoded, "-----BEGIN MESSAGE-----"),
    content="true",
  )
  inspect(string_ends_with(encoded, "-----END MESSAGE-----"), content="true")
}

///|
test "documentation_encoding_with_headers" {
  // Encoding with headers example
  let data = b"Certificate data"
  let headers : Map[String, String] = { "Version": "1.0", "Algorithm": "RSA" }
  let block = PemBlock::new(label="CERTIFICATE", data~, headers~)
  let encoded = encode(block)
  inspect(encoded.contains("Version: 1.0"), content="true")
  inspect(encoded.contains("Algorithm: RSA"), content="true")
}

///|
test "documentation_comprehensive_error_scenarios" {
  // Test all error scenarios for documentation

  // 1. Missing BEGIN marker
  let no_begin = "SGVsbG8=\n-----END MESSAGE-----"
  match decode(no_begin) {
    Err(PemError::InvalidFormat(_)) => () // Expected
    _ => fail("Should detect missing BEGIN")
  }

  // 2. Missing END marker  
  let no_end = "-----BEGIN MESSAGE-----\nSGVsbG8="
  match decode(no_end) {
    Err(PemError::InvalidFormat(_)) => () // Expected
    _ => fail("Should detect missing END")
  }

  // 3. Mismatched labels
  let mismatched = "-----BEGIN MESSAGE-----\nSGVsbG8=\n-----END CERTIFICATE-----"
  match decode(mismatched) {
    Err(PemError::MismatchedLabels(begin, end)) => {
      inspect(begin, content="MESSAGE")
      inspect(end, content="CERTIFICATE")
    }
    _ => fail("Should detect label mismatch")
  }

  // 4. Invalid base64
  let bad_base64 = "-----BEGIN MESSAGE-----\nInvalid@Base64!\n-----END MESSAGE-----"
  match decode(bad_base64) {
    Err(PemError::InvalidBase64(_)) => () // Expected
    _ => fail("Should detect invalid base64")
  }

  // 5. Empty data
  let empty_data = "-----BEGIN MESSAGE-----\n-----END MESSAGE-----"
  match decode(empty_data) {
    Err(PemError::EmptyData) => () // Expected
    _ => fail("Should detect empty data")
  }
}

///|
test "documentation_long_data_with_line_wrapping" {
  // Test line wrapping with long data
  let long_data = Bytes::from_array(Array::make(200, 65)) // 200 'A' bytes
  let block = PemBlock::new(label="LONG DATA", data=long_data)
  let encoded = encode(block)

  // Should have multiple lines due to 64-character wrapping
  let lines = encoded.split("\n") |> Iter::to_array
  inspect(lines.length() > 5, content="true")

  // Verify roundtrip
  match decode(encoded) {
    Ok(decoded) => {
      inspect(decoded.data.length(), content="200")
      inspect(decoded.label, content="LONG DATA")
    }
    Err(error) => fail("Long data roundtrip failed: \{error}")
  }
}

///|
test "documentation_certificate_chain_example" {
  // Example of handling a certificate chain
  let cert1_data = b"First certificate data"
  let cert2_data = b"Second certificate data"
  let cert3_data = b"Third certificate data"
  let cert1 = PemBlock::new(label="CERTIFICATE", data=cert1_data)
  let cert2 = PemBlock::new(label="CERTIFICATE", data=cert2_data)
  let cert3 = PemBlock::new(label="CERTIFICATE", data=cert3_data)
  let chain = encode(cert1) + "\n" + encode(cert2) + "\n" + encode(cert3)
  match decode_many(chain) {
    Ok(certificates) => {
      inspect(certificates.length(), content="3")
      inspect(
        certificates[0].data.to_string(),
        content=(
          #|b"First certificate data"
        ),
      )
      inspect(
        certificates[1].data.to_string(),
        content=(
          #|b"Second certificate data"
        ),
      )
      inspect(
        certificates[2].data.to_string(),
        content=(
          #|b"Third certificate data"
        ),
      )
    }
    Err(error) => fail("Certificate chain parsing failed: \{error}")
  }
}

///|
test "documentation_private_key_with_encryption_headers" {
  // Example of encrypted private key with headers
  let key_data = b"Encrypted private key data"
  let headers : Map[String, String] = {
    "Proc-Type": "4,ENCRYPTED",
    "DEK-Info": "AES-256-CBC,1234567890ABCDEF1234567890ABCDEF",
  }
  let key_block = PemBlock::new(
    label="RSA PRIVATE KEY",
    data=key_data,
    headers~,
  )
  let encoded = encode(key_block)

  // Verify structure
  inspect(
    string_starts_with(encoded, "-----BEGIN RSA PRIVATE KEY-----"),
    content="true",
  )
  inspect(encoded.contains("Proc-Type: 4,ENCRYPTED"), content="true")
  inspect(encoded.contains("DEK-Info: AES-256-CBC"), content="true")

  // Verify roundtrip preserves headers
  match decode(encoded) {
    Ok(decoded) => {
      inspect(decoded.headers.get("Proc-Type"), content=(
        #|Some("4,ENCRYPTED")
      ))
      inspect(
        decoded.headers.get("DEK-Info")
        |> Option::map(fn(s) { string_starts_with(s, "AES-256-CBC") }),
        content="Some(true)",
      )
    }
    Err(error) => fail("Private key roundtrip failed: \{error}")
  }
}

///|
test "decode_error_invalid_label_with_newline" {
  // Note: A newline in the label will cause the PEM format itself to be invalid,
  // so this test verifies that invalid format is detected
  let pem_data =
    #|-----BEGIN TEST
    #|LABEL-----
    #|SGVsbG8=
    #|-----END TEST
    #|LABEL-----
  let result = @pem.decode(pem_data)
  match result {
    Err(@pem.PemError::InvalidFormat(_)) =>
      // Expected - format error is detected before label validation
      ()
    Ok(_) => fail("Expected error for label with newline")
    Err(other) => fail("Unexpected error type: \{other}")
  }
}

///|
test "decode_error_invalid_label_with_colon" {
  let pem_data =
    #|-----BEGIN TEST:LABEL-----
    #|SGVsbG8=
    #|-----END TEST:LABEL-----
  let result = @pem.decode(pem_data)
  match result {
    Err(@pem.PemError::InvalidLabel(_)) =>
      // Expected
      ()
    Ok(_) => fail("Expected error for label with colon")
    Err(other) => fail("Unexpected error type: \{other}")
  }
}

///|
test "decode_error_invalid_label_with_control_char" {
  // Test with a label containing a control character (e.g., tab)
  let pem_data = "-----BEGIN TEST\tLABEL-----\nSGVsbG8=\n-----END TEST\tLABEL-----"
  let result = @pem.decode(pem_data)
  match result {
    Err(@pem.PemError::InvalidLabel(_)) =>
      // Expected
      ()
    Ok(_) => fail("Expected error for label with control character")
    Err(other) => fail("Unexpected error type: \{other}")
  }
}

///|
test "decode_valid_label_with_spaces" {
  // Spaces are valid in labels (e.g., "RSA PRIVATE KEY")
  let pem_data =
    #|-----BEGIN RSA PRIVATE KEY-----
    #|SGVsbG8=
    #|-----END RSA PRIVATE KEY-----
  let result = @pem.decode(pem_data)
  match result {
    Ok(block) => inspect(block.label, content="RSA PRIVATE KEY")
    Err(error) => fail("Valid label with spaces should not fail: \{error}")
  }
}
