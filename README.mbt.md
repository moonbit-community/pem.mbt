# PEM (Privacy-Enhanced Mail) Library

A MoonBit library for encoding and decoding PEM format data, commonly used for cryptographic keys and certificates.

## Basic Encoding

```moonbit
test "basic_encoding_example" {
  let data = b"Hello, World!"
  let block = PemBlock::new(label="MESSAGE", data~)
  let encoded = encode(block)
  
  inspect(encoded, content=(
    #|-----BEGIN MESSAGE-----
    #|SGVsbG8sIFdvcmxkIQ==
    #|-----END MESSAGE-----
  ))
}
```

## Encoding with Headers

```moonbit
test "encoding_with_headers_example" {
  let cert_data = b"Certificate data"
  let headers : Map[String, String] = { "Version": "1.0", "Algorithm": "RSA" }
  let block = PemBlock::new(label="CERTIFICATE", data=cert_data, headers~)
  let encoded = encode(block)
  
  // Verify the structure
  inspect(string_starts_with(encoded, "-----BEGIN CERTIFICATE-----"), content="true")
  inspect(encoded.contains("Version: 1.0"), content="true")
  inspect(encoded.contains("Algorithm: RSA"), content="true")
  inspect(string_ends_with(encoded, "-----END CERTIFICATE-----"), content="true")
}
```

## Basic Decoding

```moonbit
test "basic_decoding_example" {
  let pem_data = 
    #|-----BEGIN MESSAGE-----
    #|SGVsbG8sIFdvcmxkIQ==
    #|-----END MESSAGE-----
  
  let result = decode(pem_data)
  match result {
    Ok(block) => {
      assert_eq(block.label, "MESSAGE")
      assert_eq(block.data, "Hello, World!")
      assert_eq(block.headers.size(), 0)
    }
    Err(error) => fail("Unexpected error: \{error}")
  }
}
```

## Decoding with Headers

```moonbit
test "decoding_with_headers_example" {
  let pem_data = 
    #|-----BEGIN CERTIFICATE-----
    #|Version: 1.0
    #|Algorithm: RSA
    #|
    #|Q2VydGlmaWNhdGUgZGF0YQ==
    #|-----END CERTIFICATE-----
  
  let result = decode(pem_data)
  match result {
    Ok(block) => {
      assert_eq(block.label, "CERTIFICATE")
      assert_eq(block.data, "Certificate data")
      assert_eq(block.headers.get("Version"), Some("1.0"))
      assert_eq(block.headers.get("Algorithm"), Some("RSA"))
    }
    Err(error) => fail("Unexpected error: \{error}")
  }
}
```

## Decoding Multiple Blocks

```moonbit
test "multiple_blocks_example" {
  let multi_pem = 
    #|-----BEGIN FIRST-----
    #|Zmlyc3Q=
    #|-----END FIRST-----
    #|-----BEGIN SECOND-----
    #|c2Vjb25k
    #|-----END SECOND-----
  
  let result = decode_many(multi_pem)
  match result {
    Ok(blocks) => {
      assert_eq(blocks.length(), 2)
      assert_eq(blocks[0].label, "FIRST")
      assert_eq(blocks[0].data, "first")
      assert_eq(blocks[1].label, "SECOND")
      assert_eq(blocks[1].data, "second")
    }
    Err(error) => fail("Unexpected error: \{error}")
  }
}
```

## Error Handling

```moonbit
test "error_handling_examples" {
  // Test invalid format
  let invalid_pem = "not a pem file"
  let result1 = decode(invalid_pem)
  match result1 {
    Err(PemError::InvalidFormat(msg)) => {
      inspect(msg, content="PEM data too short")
    }
    _ => fail("Should have failed with InvalidFormat")
  }
  
  // Test missing BEGIN marker
  let no_begin = "SGVsbG8=\n-----END MESSAGE-----"
  let result2 = decode(no_begin)
  match result2 {
    Err(PemError::InvalidFormat(_)) => () // Expected
    _ => fail("Should detect missing BEGIN")
  }
  
  // Test mismatched labels
  let mismatched = "-----BEGIN MESSAGE-----\nSGVsbG8=\n-----END CERTIFICATE-----"
  let result3 = decode(mismatched)
  match result3 {
    Err(PemError::MismatchedLabels(begin, end)) => {
      inspect(begin, content="MESSAGE")
      inspect(end, content="CERTIFICATE")
    }
    _ => fail("Should detect label mismatch")
  }
  
  // Test invalid base64
  let bad_base64 = "-----BEGIN MESSAGE-----\nInvalid@Base64!\n-----END MESSAGE-----"
  let result4 = decode(bad_base64)
  match result4 {
    Err(PemError::InvalidBase64(_)) => () // Expected
    _ => fail("Should detect invalid base64")
  }
}
```

## Roundtrip Example

```moonbit
test "roundtrip_example" {
  let original_data = b"Any binary data can be encoded in PEM format"
  let headers : Map[String, String] = { "Type": "Example", "Version": "1.0" }
  
  // Encode
  let block = PemBlock::new(label="DATA", data=original_data, headers~)
  let encoded = encode(block)
  
  // Decode
  let result = decode(encoded)
  match result {
    Ok(decoded) => {
      assert_eq(decoded.label, "DATA")
      assert_eq(decoded.data.to_string(), original_data.to_string())
      assert_eq(decoded.headers.get("Type"), Some("Example"))
      assert_eq(decoded.headers.get("Version"), Some("1.0"))
    }
    Err(error) => fail("Roundtrip failed: \{error}")
  }
}
```

## Certificate Example

```moonbit
test "certificate_example" {
  let cert_data = b"Mock X.509 certificate data"
  let cert_block = PemBlock::new(label="CERTIFICATE", data=cert_data)
  let pem_string = encode(cert_block)
  
  // Verify certificate format
  assert_true(string_starts_with(pem_string, "-----BEGIN CERTIFICATE-----"))
  assert_true(string_ends_with(pem_string, "-----END CERTIFICATE-----"))

  // Verify it can be decoded back
  let result = decode(pem_string)
  match result {
    Ok(decoded) => {
      assert_eq(decoded.label, "CERTIFICATE")
      assert_eq(decoded.data, "Mock X.509 certificate data")
    }
    Err(error) => fail("Certificate roundtrip failed: \{error}")
  }
}
```

## Private Key Example

```moonbit
test "private_key_example" {
  let key_data = b"Mock RSA private key data"
  let headers : Map[String, String] = { 
    "Proc-Type": "4,ENCRYPTED",
    "DEK-Info": "AES-256-CBC,1234567890ABCDEF"
  }
  let key_block = PemBlock::new(label="RSA PRIVATE KEY", data=key_data, headers~)
  let pem_string = encode(key_block)
  
  // Verify private key format
  inspect(string_starts_with(pem_string, "-----BEGIN RSA PRIVATE KEY-----"), content="true")
  inspect(pem_string.contains("Proc-Type: 4,ENCRYPTED"), content="true")
  inspect(pem_string.contains("DEK-Info: AES-256-CBC"), content="true")
  
  // Verify headers are preserved
  let result = decode(pem_string)
  match result {
    Ok(decoded) => {
      assert_eq(decoded.headers.get("Proc-Type"), Some("4,ENCRYPTED"))
      inspect(decoded.headers.get("DEK-Info") |> Option::map(fn(s) { string_starts_with(s, "AES-256-CBC") }), content="Some(true)")
    }
    Err(error) => fail("Private key roundtrip failed: \{error}")
  }
}
```

## Certificate Chain Example

```moonbit
test "certificate_chain_example" {
  // Create a certificate chain
  let root_cert = PemBlock::new(label="CERTIFICATE", data=b"Root CA certificate")
  let intermediate_cert = PemBlock::new(label="CERTIFICATE", data=b"Intermediate certificate")
  let leaf_cert = PemBlock::new(label="CERTIFICATE", data=b"Leaf certificate")
  
  // Combine into a chain
  let chain_pem = encode(root_cert) + "\n" + encode(intermediate_cert) + "\n" + encode(leaf_cert)
  
  // Parse the chain
  let result = decode_many(chain_pem)
  match result {
    Ok(certificates) => {
      assert_eq(certificates.length(), 3)
      assert_eq(certificates[0].data, "Root CA certificate")
      assert_eq(certificates[1].data, "Intermediate certificate")
      assert_eq(certificates[2].data, "Leaf certificate")

      // All should be certificates
      for cert in certificates {
        assert_eq(cert.label, "CERTIFICATE")
      }
    }
    Err(error) => fail("Certificate chain parsing failed: \{error}")
  }
}
```

## Long Data with Line Wrapping

```moonbit
test "long_data_line_wrapping_example" {
  // Create data that will require line wrapping (more than 64 base64 chars)
  let long_data = Bytes::from_array(Array::make(150, 65)) // 150 'A' bytes
  let block = PemBlock::new(label="LONG DATA", data=long_data)
  let encoded = encode(block)
  
  // Verify line wrapping occurred
  let lines = encoded.split("\n") |> Iter::to_array
  inspect(lines.length() > 4, content="true") // Should have multiple data lines
  
  // Verify roundtrip works with long data
  let result = decode(encoded)
  match result {
    Ok(decoded) => {
      inspect(decoded.data.length(), content="150")
      inspect(decoded.label, content="LONG DATA")
      // Verify all bytes are 'A' (65)
      for i = 0; i < decoded.data.length(); i = i + 1 {
        if decoded.data[i].to_int() != 65 {
          fail("Unexpected byte at position \{i}")
        }
      }
    }
    Err(error) => fail("Long data roundtrip failed: \{error}")
  }
}
```

## Mixed Block Types

```moonbit
test "mixed_block_types_example" {
  // Create different types of PEM blocks
  let cert = PemBlock::new(label="CERTIFICATE", data=b"Certificate data")
  let pubkey = PemBlock::new(label="PUBLIC KEY", data=b"Public key data")
  let privkey = PemBlock::new(label="PRIVATE KEY", data=b"Private key data")
  
  // Combine different block types
  let mixed_pem = encode(cert) + "\n" + encode(pubkey) + "\n" + encode(privkey)
  
  // Parse all blocks
  let result = decode_many(mixed_pem)
  match result {
    Ok(blocks) => {
      inspect(blocks.length(), content="3")
      
      // Verify each block type
      assert_eq(blocks[0].label, "CERTIFICATE")
      assert_eq(blocks[0].data, "Certificate data")

      assert_eq(blocks[1].label, "PUBLIC KEY")
      assert_eq(blocks[1].data, "Public key data")

      assert_eq(blocks[2].label, "PRIVATE KEY")
      assert_eq(blocks[2].data, "Private key data")
    }
    Err(error) => fail("Mixed blocks parsing failed: \{error}")
  }
}
```

## Empty and Edge Cases

```moonbit
test "edge_cases_example" {
  // Test empty data
  let empty_block = PemBlock::new(label="EMPTY", data=b"")
  let empty_encoded = encode(empty_block)
  
  inspect(string_starts_with(empty_encoded, "-----BEGIN EMPTY-----"), content="true")
  inspect(string_ends_with(empty_encoded, "-----END EMPTY-----"), content="true")
  
  // Test minimal valid PEM
  let minimal_pem = 
    #|-----BEGIN TEST-----
    #|QQ==
    #|-----END TEST-----
  
  let result = decode(minimal_pem)
  match result {
    Ok(block) => {
      assert_eq(block.label, "TEST")
      assert_eq(block.data, "A")
    }
    Err(error) => fail("Minimal PEM failed: \{error}")
  }
  
  // Test PEM with only headers and no data should fail
  let headers_only = 
    #|-----BEGIN HEADERS-----
    #|Key: Value
    #|-----END HEADERS-----
  
  let result2 = decode(headers_only)
  match result2 {
    Err(PemError::EmptyData) => () // Expected
    _ => fail("Should detect empty data")
  }
}
```
