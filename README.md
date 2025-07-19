# 🦾 Ebyte-Go-Morpher

A technical overview of the Go source code obfuscator as implemented in `tools/genobf.go`.

---

## 📖 Description

Ebyte-Go-Morpher is a Go program that parses, analyzes, and rewrites Go source code to apply multiple layers of obfuscation. It operates directly on the Go Abstract Syntax Tree (AST) and generates both obfuscated source files and runtime decryption logic.

---

## 🏗️ Core Design
- **Language:** Go
- **Entry Point:** `main()` in `tools/genobf.go`
- **Primary Function:** Obfuscates Go source code by traversing and rewriting the AST using Go’s standard library.

---

## 🧩 Key Components

### 🔒 Obfuscator Types
- **StringObfuscator**: Encrypts string literals (XOR with random key), generates a unique function for each, and replaces calls to `OBF("...")` with these functions.
- **NumberObfuscator**: Replaces integer literals with Mixed Boolean-Arithmetic (MBA) expressions, e.g., `a = 42` → `a = (100 ^ 78)`.
- **IdentifierObfuscator**: Renames variables, functions, and local identifiers using FNV hash-based names (e.g., `OBF_ABCDEF`).
- **TypeObfuscator**: Renames struct types and tracks type references, including recursive types.
- **FieldObfuscator**: Renames struct fields, preserving field tags for reflection.
- **FunctionObfuscator**: Renames functions (except special ones like `main`, `init`, etc.).
- **MBAObfuscator**: Applies De Morgan’s laws and algebraic rewrites to boolean and arithmetic expressions.

### 🌳 AST Processing
- **ASTProcessor**: Walks the AST, applies obfuscation logic, manages variable/function scope, and delegates to the appropriate obfuscator.
- **Scope Tracking**: Ensures local variable renaming is collision-free and context-aware.

### 📂 File Processing
- **FileProcessor**: Handles reading, parsing, and rewriting Go files. Applies obfuscation and writes changes back to disk.

### 🏭 Code Generation
- **CodeGenerator**: Generates `include/preproc.go` containing all runtime decryption and obfuscation logic for strings and numbers.

### ⚙️ Configuration
- **Config struct**: Controls which obfuscation features are enabled, which directories to skip, and output directory for generated code.

---

## 🔄 Workflow
1. 🔍 **Scan Files**: Recursively walks the project directory, skipping configured folders (`vendor`, `tools`, `include` by default).
2. 🧠 **Parse & Analyze**: Parses each `.go` file into an AST.
3. 🦾 **Obfuscate**: Applies string, number, identifier, type, field, and MBA obfuscation as configured.
4. 🏭 **Generate Code**: Writes decryption/obfuscation logic to `include/preproc.go`.
5. ✍️ **Rewrite Source**: Updates original source files to use obfuscated names and function calls.

---

## 🚀 Supported Features
- 🔐 **String encryption** for any string wrapped in `OBF()`
- 🔢 **Number obfuscation** for all integer literals (except 0, 1, and constants)
- 🏷️ **Identifier renaming** for all local variables, functions, types, and struct fields (with scope awareness)
- 🧬 **Type and field obfuscation** for structs and their fields, with tag preservation
- 🧮 **MBA transformations** for boolean and arithmetic expressions
- 🛠️ **Configurable**: All features can be toggled in `NewConfig()`

---

## ⚠️ Limitations
- 🚫 **Does not obfuscate constants** (Go `const` values are skipped)
- 🛡️ **Does not obfuscate exported identifiers by default** (unless configured)
- 🪞 **Reflection compatibility**: Field tags are preserved, but heavy reflection use may need extra care
- 📁 **Only processes `.go` files**; skips `vendor`, `tools`, and `include` by default

---

## 🛠️ Notable Implementation Details
- 📚 **Uses Go’s standard library for AST manipulation** (`go/ast`, `go/parser`, `go/token`)
- 🏷️ **Uses FNV hash for deterministic obfuscated names**
- 🎲 **Randomness for encryption and MBA expressions** is sourced from `crypto/rand` and `math/rand`
- 🧹 **Generated code is formatted with `gofmt`** after writing

---

## 📝 Example (from code logic)

- main_test_input.go (for input, before)
- main_test_output.go (for output, after)

---

## 🏃 Usage
1. 📂 Place your Go project in the workspace.
2. ▶️ Run the obfuscator:
   ```sh
   go generate 
   go run .
   ```
3. 📦 Obfuscated files and generated code will be written in-place and to the `include/` directory.

---

## ⚙️ Configuration
Edit the `NewConfig()` function in `tools/genobf.go` to customize:
- 📁 Directories to skip (`SkipDirs`)
- 🏷️ Obfuscation tag for functions (`ObfuscateTag`)
- 📦 Output directory for generated code (`OutputDir`)
- 🛠️ Toggle obfuscation for structs, variables, numbers, types, MBA, and fields
---
```go
func NewConfig() *Config {
	return &Config{
		SkipDirs:         []string{"vendor", "tools", "include"},
		ObfuscateTag:     "//obfuscate:function",
		OutputDir:        "include",
		ObfuscateStructs: true,
		ObfuscateVars:    true,
		ObfuscateNumbers: true,
		ObfuscateTypes:   true,
		ObfuscateMBA:     true,
		ObfuscateFields:  true, 
	}
}
```
---

## 📄 License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
