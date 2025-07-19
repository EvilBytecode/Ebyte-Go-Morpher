/*
 * │ Author       : Evilbytecode
 * │ Name         : Ebyte-Go-Morpher
 * │ Contact      : https://github.com/Evilbytecode
 *
 * This program is distributed for educational purposes only.
 *
 * Technical Overview:
 *   - Ebyte-Go-Obfuscator is a comprehensive Go source code obfuscator.
 *   - It parses Go source files using the go/ast and go/parser packages, traverses the AST, and applies multiple layers of obfuscation.
 *   - Supported obfuscation features:
 *       • String encryption: All string literals wrapped in OBF() are encrypted and replaced with runtime-decrypted functions.
 *       • Number obfuscation: Integer literals are replaced with equivalent, more complex expressions.
 *       • Identifier renaming: Variables, functions, types, and struct fields are renamed using hash-based schemes.
 *       • Type and field obfuscation: Struct types and their fields are renamed, with field tags preserved.
 *       • MBA (Mixed Boolean-Arithmetic) transformations: Boolean and arithmetic expressions are rewritten for complexity, using techniques such as De Morgan's laws and algebraic identities.
 *       • Scope-aware renaming: Local variables are renamed with respect to their scope, avoiding collisions.
 *       • Configurable: Obfuscation can be toggled for structs, variables, numbers, types, MBA, and fields.
 *       • Code generation: Generates a Go file with all decryption and obfuscation logic for runtime use.
 *       • Source rewriting: Rewrites original source files to use obfuscated names and encrypted values.
 *   - Workflow:
 *       1. Scan and parse all Go files in the project (excluding configured directories).
 *       2. Collect and encrypt all strings/numbers marked for obfuscation.
 *       3. Rename identifiers, types, and fields as configured.
 *       4. Apply MBA and other code transformations (e.g., De Morgan's laws, algebraic rewrites).
 *       5. Generate a new Go file with decryption logic.
 *       6. Rewrite source files to use obfuscated names and function calls.
 *
 * References & Inspiration:
 *   - Inspired by Go's official AST tools, various open-source obfuscators, and advanced code protection techniques.
 *   - Notable references: Golang's go/ast, go/parser, go/printer, and projects like garble, gobfuscate, and commercial obfuscators.
 *   - Mixed Boolean-Arithmetic (MBA) obfuscation: see https://en.wikipedia.org/wiki/Obfuscation_(software)#Mixed_boolean-arithmetic_obfuscation
 *   - De Morgan's laws: https://en.wikipedia.org/wiki/De_Morgan%27s_laws
 *   - Algebraic and logical code transformations: see academic papers on code obfuscation and compiler theory.
 *   - For more info, see: https://github.com/Evilbytecode/Ebyte-Go-Morpher
 *
 * Legal & Distribution:
 *   - This software is provided under the terms of the MIT License (or specify your license here).
 *   - You must comply with all applicable local, national, and international laws regarding software use, cryptography, and reverse engineering.
 *   - The author is not responsible for any misuse or illegal use of this software.
 *   - Obfuscation techniques implemented here are based on well-known mathematical and logical laws (e.g., De Morgan's laws, algebraic identities) and standard cryptographic practices for string encryption (XOR, random key generation).
 *   - Users are responsible for ensuring compliance with export controls, cryptography regulations, and intellectual property laws in their jurisdiction.
 */
package main

import (
	"crypto/rand"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"
	"bytes"
	"hash/fnv"
	"os/exec"
	"strconv"
	mathrand "math/rand"
	"math"
)

func isSpecialFunc(name string) bool {
	return name == "init" || name == "main" || name == "String" || 
	       strings.HasPrefix(name, "Must") || strings.HasPrefix(name, "Test")
}

func isConstExpr(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.BinaryExpr:
		return isConstExpr(e.X) && isConstExpr(e.Y)
	case *ast.BasicLit:
		return true
	case *ast.Ident:
		return e.Obj != nil && e.Obj.Kind == ast.Con
	}
	return false
}

func isInterface(expr ast.Expr) bool {
	if iface, ok := expr.(*ast.InterfaceType); ok {
		return iface != nil
	}
	return false
}

func shouldSkipType(name string) bool {
	return strings.HasPrefix(name, "Test") || 
	       strings.HasSuffix(name, "Interface") ||
	       strings.HasSuffix(name, "Error")
}

// ===== DATA STRUCTURES =====

type StringInfo struct {
	Original  string
	Encrypted []byte
	Key       byte
	Ident     string
}

type IdentifierInfo struct {
	Original string
	ObfName  string
}

type NumberInfo struct {
	Original int64
	ObfExpr  string
	Ident    string
}

type TypeInfo struct {
	Original    string
	ObfName     string
	References  map[string]bool 
	IsRecursive bool           
}

type Config struct {
	SkipDirs          []string
	ObfuscateTag      string
	OutputDir         string
	ObfuscateStructs  bool
	ObfuscateVars     bool
	ObfuscateNumbers  bool
	ObfuscateTypes    bool
	ObfuscateMBA      bool
	ObfuscateFields   bool  
}

func (c *Config) ShouldObfuscateVar(name string) bool {
	return c.ObfuscateVars && name != "" && !ast.IsExported(name)
}

func (c *Config) ShouldObfuscateField(name string) bool {
	return (c.ObfuscateFields || c.ObfuscateStructs) && name != "" && (!ast.IsExported(name) || c.ObfuscateFields)
}

func addObfuscated[T any](m map[string]*T, key string, create func() *T) *T {
	if info, exists := m[key]; exists {
		return info
	}
	info := create()
	m[key] = info
	return info
}

// ===== UTILITY FUNCTIONS =====

func GenerateHash(prefix, value string) string {
	h := fnv.New64a()
	h.Write([]byte(fmt.Sprintf("%s_%s", prefix, value)))
	return fmt.Sprintf("OBF_%X", h.Sum64())
}

func ReadParseFile(fset *token.FileSet, filename string) (*ast.File, error) {
	src, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %v", filename, err)
	}
	
	node, err := parser.ParseFile(fset, filename, src, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %v", filename, err)
	}
	
	return node, nil
}

func WriteFormattedFile(filename string, node *ast.File, fset *token.FileSet) error {
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, node); err != nil {
		return fmt.Errorf("failed to print AST: %v", err)
	}
	
	if err := os.WriteFile(filename, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %v", filename, err)
	}
	
	cmd := exec.Command("gofmt", "-w", filename)
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: gofmt failed on %s: %v\n", filename, err)
	}
	
	return nil
}

func extractString(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind == token.STRING {
			return strings.Trim(e.Value, `"`)
		}
	case *ast.BinaryExpr:
		return extractString(e.X) + extractString(e.Y)
	}
	return ""
}

func isObfCall(call *ast.CallExpr) bool {
	if len(call.Args) != 1 {
		return false
	}
	switch f := call.Fun.(type) {
	case *ast.SelectorExpr:
		if ident, ok := f.X.(*ast.Ident); ok {
			if ident.Name == "include" && (f.Sel.Name == "OBF" || strings.HasPrefix(f.Sel.Name, "OBF_")) {
				return true
			}
		}
	case *ast.Ident:
		if f.Name == "OBF" || strings.HasPrefix(f.Name, "OBF_") {
			return true
		}
	}
	return false
}

func extractStringFromArg(arg ast.Expr) string {
	switch a := arg.(type) {
	case *ast.BasicLit:
		if a.Kind == token.STRING {
			return strings.Trim(a.Value, `"`)
		}
	case *ast.BinaryExpr:
		if a.Op == token.ADD {
			left := extractString(a.X)
			right := extractString(a.Y)
			if left != "" && right != "" {
				return left + right
			}
		}
	}
	return ""
}

// ===== STRING OBFUSCATOR  =====

type StringObfuscator struct {
	strings map[string]*StringInfo
}

func NewStringObfuscator() *StringObfuscator {
	return &StringObfuscator{
		strings: make(map[string]*StringInfo),
	}
}

func (s *StringObfuscator) StringEncrypt(str string) *StringInfo {
	keyBytes := make([]byte, 1)
	if _, err := rand.Read(keyBytes); err != nil {
		panic(fmt.Sprintf("failed to generate random key: %v", err))
	}
	key := keyBytes[0]

	data := []byte(str)
	encrypted := make([]byte, len(data))
	for i := range data {
		encrypted[i] = data[i] ^ key
	}

	return &StringInfo{
		Original:  str,
		Encrypted: encrypted,
		Key:       key,
		Ident:     GenerateHash("string", str),
	}
}

func (s *StringObfuscator) AddString(str string) *StringInfo {
	if info, exists := s.strings[str]; exists {
		return info
	}

	info := s.StringEncrypt(str)
	s.strings[str] = info
	return info
}

func (s *StringObfuscator) GetAllStrings() []*StringInfo {
	var strings []*StringInfo
	for _, info := range s.strings {
		strings = append(strings, info)
	}
	sort.Slice(strings, func(i, j int) bool {
		return strings[i].Ident < strings[j].Ident
	})
	return strings
}

// ===== NUMBER OBFUSCATOR  =====

type NumberObfuscator struct {
	numbers map[int64]*NumberInfo
}

func NewNumberObfuscator() *NumberObfuscator {
	return &NumberObfuscator{
		numbers: make(map[int64]*NumberInfo),
	}
}

func (n *NumberObfuscator) GenerateNumberExpression(num int64) string {
	if num == 0 {
		return "0"
	}
	if num == 1 {
		return "1"
	}
	
	mbaType := mathrand.Intn(3)
	keyBytes := make([]byte, 4)
	if _, err := rand.Read(keyBytes); err != nil {
		panic(fmt.Sprintf("failed to generate random key: %v", err))
	}
	key := int64(keyBytes[0]) | int64(keyBytes[1])<<8 | int64(keyBytes[2])<<16 | int64(keyBytes[3])<<24
	key = key%1000 + 1
	
	switch mbaType {
	case 0:
		result := num + key
		return fmt.Sprintf("(%d - %d)", result, key)
	case 1:
		xorkey := key & 0xFF
		result := num ^ xorkey
		return fmt.Sprintf("(%d ^ %d)", result, xorkey)
	default: // case 2
		key2 := (key * 2) % 1000 + 1
		result := num + key2
		return fmt.Sprintf("(%d - %d)", result, key2)
	}
}

func (n *NumberObfuscator) AddNumber(num int64) *NumberInfo {
	if info, exists := n.numbers[num]; exists {
		return info
	}
	
	obfExpr := n.GenerateNumberExpression(num)
	info := &NumberInfo{
		Original: num,
		ObfExpr:  obfExpr,
		Ident:    GenerateHash("num", fmt.Sprintf("%d", num)),
	}
	n.numbers[num] = info
	return info
}

func (n *NumberObfuscator) GetAllNumbers() []*NumberInfo {
	var numbers []*NumberInfo
	for _, info := range n.numbers {
		numbers = append(numbers, info)
	}
	sort.Slice(numbers, func(i, j int) bool {
		return numbers[i].Ident < numbers[j].Ident
	})
	return numbers
}

// ===== IDENTIFIER OBFUSCATOR  =====

type IdentifierObfuscator struct {
	identifiers map[string]*IdentifierInfo
}

func NewIdentifierObfuscator() *IdentifierObfuscator {
	return &IdentifierObfuscator{
		identifiers: make(map[string]*IdentifierInfo),
	}
}

func (i *IdentifierObfuscator) AddIdentifier(name string) *IdentifierInfo {
	return addObfuscated(i.identifiers, name, func() *IdentifierInfo {
		return &IdentifierInfo{
			Original: name,
			ObfName:  GenerateHash("ident", name),
		}
	})
}

func (i *IdentifierObfuscator) GetObfuscatedName(name string) (string, bool) {
	if info, exists := i.identifiers[name]; exists {
		return info.ObfName, true
	}
	return "", false
}

// ===== TYPE OBFUSCATOR  =====

type TypeObfuscator struct {
	types map[string]*TypeInfo
}

func NewTypeObfuscator() *TypeObfuscator {
	return &TypeObfuscator{
		types: make(map[string]*TypeInfo),
	}
}

func (t *TypeObfuscator) AddType(name string) *TypeInfo {
	if shouldSkipType(name) {
		return nil
	}
	
	if info, exists := t.types[name]; exists {
		return info
	}
	
	info := &TypeInfo{
		Original:    name,
		ObfName:     GenerateHash("type", name),
		References:  make(map[string]bool),
		IsRecursive: false,
	}
	t.types[name] = info
	return info
}

func (t *TypeObfuscator) AddTypeReference(typeName, referencedType string) {
	if info, exists := t.types[typeName]; exists {
		info.References[referencedType] = true
		if typeName == referencedType {
			info.IsRecursive = true
		}
	}
}

func (t *TypeObfuscator) GetObfuscatedName(name string) (string, bool) {
	if info, exists := t.types[name]; exists {
		return info.ObfName, true
	}
	return "", false
}

// ===== FUNCTION OBFUSCATOR  =====

type FunctionObfuscator struct {
	funcRenameMap map[string]string
}

func NewFunctionObfuscator() *FunctionObfuscator {
	return &FunctionObfuscator{
		funcRenameMap: make(map[string]string),
	}
}

func (f *FunctionObfuscator) AddFunction(name string) string {
	if newName, exists := f.funcRenameMap[name]; exists {
		return newName
	}
	
	newName := GenerateHash("func", name)
	f.funcRenameMap[name] = newName
	return newName
}

func (f *FunctionObfuscator) GetObfuscatedName(name string) (string, bool) {
	if newName, exists := f.funcRenameMap[name]; exists {
		return newName, true
	}	
	return "", false
}

// ===== MBA OBFUSCATOR =====
// For logical operations, we can use De Morgan's laws
// !(A && B) = !A || !B
// !(A || B) = !A && !B

type MBAObfuscator struct{}

func NewMBAObfuscator() *MBAObfuscator {
	return &MBAObfuscator{}
}

func (m *MBAObfuscator) ObfuscateCondition(expr ast.Expr) ast.Expr {
	if bin, ok := expr.(*ast.BinaryExpr); ok {
		return m.ObfuscateBinaryExpr(bin)
	}
	if unary, ok := expr.(*ast.UnaryExpr); ok {
		return m.ObfuscateUnaryExpr(unary)
	}
	if paren, ok := expr.(*ast.ParenExpr); ok {
		paren.X = m.ObfuscateCondition(paren.X)
		return paren
	}
	
	return expr
}

func (m *MBAObfuscator) ObfuscateBinaryExpr(bin *ast.BinaryExpr) ast.Expr {
	bin.X = m.ObfuscateCondition(bin.X)
	bin.Y = m.ObfuscateCondition(bin.Y)
   switch bin.Op {
	case token.EQL, token.NEQ, token.LSS, token.GTR, token.LEQ, token.GEQ:
		return m.ObfuscateComparison(bin)
	case token.LAND, token.LOR:
		return m.ObfuscateLogicalOp(bin)
	case token.ADD, token.SUB, token.MUL, token.QUO, token.REM:
		return m.ObfuscateArithmeticOp(bin)
	}
	
	return bin
}

func (m *MBAObfuscator) ObfuscateUnaryExpr(unary *ast.UnaryExpr) ast.Expr {
	unary.X = m.ObfuscateCondition(unary.X)
	return unary
}

func (m *MBAObfuscator) createTransformation(bin *ast.BinaryExpr, key int, op token.Token) ast.Expr {
	left := &ast.BinaryExpr{
		X:  bin.X,
		Op: op,
		Y:  &ast.BasicLit{Kind: token.INT, Value: fmt.Sprintf("%d", key)},
	}
	
	right := &ast.BinaryExpr{
		X:  bin.Y,
		Op: op,
		Y:  &ast.BasicLit{Kind: token.INT, Value: fmt.Sprintf("%d", key)},
	}
	
	return &ast.BinaryExpr{X: left, Op: bin.Op, Y: right}
}

func (m *MBAObfuscator) ObfuscateComparison(bin *ast.BinaryExpr) ast.Expr {
	if m.ContainsNilOrSpecialValue(bin.X) || m.ContainsNilOrSpecialValue(bin.Y) {
		return bin
	}
	key := mathrand.Intn(1000) + 1
	transformType := mathrand.Intn(3)
	switch transformType {
	case 0:
		return m.createTransformation(bin, key, token.XOR)
	case 1:
		return m.createTransformation(bin, key, token.ADD)
	default: 
		return m.createTransformation(bin, key, token.MUL)
	}
}

func (m *MBAObfuscator) ObfuscateLogicalOp(bin *ast.BinaryExpr) ast.Expr {
	if m.ContainsNilOrSpecialValue(bin.X) || m.ContainsNilOrSpecialValue(bin.Y) {
		return bin
	}
	if mathrand.Intn(2) == 0 {
		notLeft := &ast.UnaryExpr{Op: token.NOT, X: bin.X}
		notRight := &ast.UnaryExpr{Op: token.NOT, X: bin.Y}
		var newOp token.Token
		if bin.Op == token.LAND {
			newOp = token.LOR
		} else {
			newOp = token.LAND
		}
		inner := &ast.BinaryExpr{X: notLeft, Op: newOp, Y: notRight}
		return &ast.UnaryExpr{Op: token.NOT, X: inner}
	}
	return bin
}

func (m *MBAObfuscator) ObfuscateArithmeticOp(bin *ast.BinaryExpr) ast.Expr {
	if m.ContainsNilOrSpecialValue(bin.X) || m.ContainsNilOrSpecialValue(bin.Y) {
		return bin
	}
	key := mathrand.Intn(100) + 1
	switch bin.Op {
	case token.ADD:
		left := &ast.BinaryExpr{
			X:  bin.X,
			Op: token.ADD,
			Y:  &ast.BasicLit{Kind: token.INT, Value: fmt.Sprintf("%d", key)},
		}
		right := &ast.BinaryExpr{
			X:  bin.Y,
			Op: token.SUB,
			Y:  &ast.BasicLit{Kind: token.INT, Value: fmt.Sprintf("%d", key)},
		}
		return &ast.BinaryExpr{X: left, Op: token.ADD, Y: right}
	case token.SUB:
		return m.createTransformation(bin, key, token.ADD)
	}
	return bin
}

func (m *MBAObfuscator) ContainsNilOrSpecialValue(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name == "nil"
	case *ast.BasicLit:
		if e.Kind == token.STRING {
			value := strings.Trim(e.Value, `"`)
			return value == "nil" || value == "true" || value == "false"
		}
	}
	return false
}

// ===== FIELD OBFUSCATOR =====

type FieldObfuscator struct {
	fields map[string]*FieldInfo
}

type FieldInfo struct {
	Original string
	ObfName  string
	Tag      string    
}

func NewFieldObfuscator() *FieldObfuscator {
	return &FieldObfuscator{
		fields: make(map[string]*FieldInfo),
	}
}

func (f *FieldObfuscator) AddField(name string) *FieldInfo {
	return addObfuscated(f.fields, name, func() *FieldInfo {
		return &FieldInfo{
			Original: name,
			ObfName:  GenerateHash("field", name),
			Tag:      "",
		}
	})
}

func (f *FieldObfuscator) GetObfuscatedName(name string) (string, bool) {
	if info, exists := f.fields[name]; exists {
		return info.ObfName, true
	}
	return "", false
}

// ===== AST PROCESSOR  =====

type Scope struct {
	parent    *Scope
	variables map[string]string  
}

type ASTProcessor struct {
	stringObf      *StringObfuscator
	numberObf      *NumberObfuscator
	identifierObf  *IdentifierObfuscator
	typeObf        *TypeObfuscator
	functionObf    *FunctionObfuscator
	mbaObf         *MBAObfuscator
	fieldObf       *FieldObfuscator
	config         *Config
	currentFile    *ast.File
	currentScope   *Scope        
}

func NewScope(parent *Scope) *Scope {
	return &Scope{
		parent:    parent,
		variables: make(map[string]string),
	}
}

func (s *Scope) Get(name string) (string, bool) {
	if obf, ok := s.variables[name]; ok {
		return obf, true
	}
	if s.parent != nil {
		return s.parent.Get(name)
	}
	return "", false
}

func (s *Scope) Add(original, obfuscated string) {
	s.variables[original] = obfuscated
}

func NewASTProcessor(config *Config) *ASTProcessor {
	return &ASTProcessor{
		stringObf:     NewStringObfuscator(),
		numberObf:     NewNumberObfuscator(),
		identifierObf: NewIdentifierObfuscator(),
		typeObf:       NewTypeObfuscator(),
		functionObf:   NewFunctionObfuscator(),
		mbaObf:        NewMBAObfuscator(),
		fieldObf:      NewFieldObfuscator(),
		config:        config,
		currentFile:   nil,
		currentScope:  NewScope(nil),  
	}
}

func (ap *ASTProcessor) ProcessFuncDecl(fn *ast.FuncDecl) {
	oldScope := ap.currentScope
	ap.currentScope = NewScope(oldScope)
	defer func() { ap.currentScope = oldScope }()

	if isSpecialFunc(fn.Name.Name) {
		return
	}

	if fn.Recv != nil {
		for _, field := range fn.Recv.List {
			if isInterface(field.Type) {
				return
			}
		}
	}

	shouldObfuscate := false
	if fn.Doc != nil {
		for _, comment := range fn.Doc.List {
			if strings.TrimSpace(comment.Text) == ap.config.ObfuscateTag {
				shouldObfuscate = true
				ap.functionObf.AddFunction(fn.Name.Name)
				break
			}
		}
	}

	ap.obfuscateFuncParams(fn, shouldObfuscate)
	ap.obfuscateFuncBody(fn)
}

func (ap *ASTProcessor) obfuscateFuncParams(fn *ast.FuncDecl, shouldObfuscate bool) {
	if fn.Type.Params != nil {
		for _, field := range fn.Type.Params.List {
			for _, name := range field.Names {
				if name.Name != "" {
					if shouldObfuscate || !ast.IsExported(name.Name) {
						originalName := name.Name
						obfName := ap.identifierObf.AddIdentifier(name.Name).ObfName
						ap.currentScope.Add(originalName, obfName)
						name.Name = obfName
					}
				}
			}
		}
	}
}

func (ap *ASTProcessor) obfuscateFuncBody(fn *ast.FuncDecl) {
	if fn.Body != nil {
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.Ident:
				if node == fn.Name {
					return true
				}
				if obfName, ok := ap.currentScope.Get(node.Name); ok {
					node.Name = obfName
				} else if !ast.IsExported(node.Name) && !strings.HasPrefix(node.Name, "OBF_") {
					obfName := ap.identifierObf.AddIdentifier(node.Name).ObfName
					ap.currentScope.Add(node.Name, obfName)
					node.Name = obfName
				}
			}
			return true
		})
	}
}

func (ap *ASTProcessor) ProcessNode(n ast.Node) bool {
	switch node := n.(type) {
	case *ast.CallExpr:
		ap.ProcessCallExpr(node)
	case *ast.BasicLit:
		ap.ProcessBasicLit(node)
	case *ast.TypeSpec:
		ap.ProcessTypeSpec(node)
	case *ast.Field:
		ap.ProcessField(node)
	case *ast.AssignStmt:
		ap.ProcessAssignStmt(node)
	case *ast.GenDecl:
		ap.ProcessGenDecl(node)
	case *ast.FuncDecl:
		ap.ProcessFuncDecl(node)
	case *ast.IfStmt:
		ap.ProcessIfStmt(node)
	case *ast.ForStmt:
		ap.ProcessForStmt(node)
	case *ast.SwitchStmt:
		ap.ProcessSwitchStmt(node)
	}
	return true
}

func (ap *ASTProcessor) ProcessCallExpr(call *ast.CallExpr) {
	if !isObfCall(call) {
		return
	}
	str := extractStringFromArg(call.Args[0])
	if str != "" {
		ap.stringObf.AddString(str)
	}
}

func (ap *ASTProcessor) ProcessBasicLit(lit *ast.BasicLit) {
	if !ap.config.ObfuscateNumbers {
		return
	}

	if lit.Kind != token.INT || isConstExpr(lit) {
		return
	}

	num, err := strconv.ParseInt(lit.Value, 10, 64)
	if err != nil {
		return
	}

	// we support only numbers within int64 range (Go's default for integer literals)
	if num < math.MinInt64 || num > math.MaxInt64 {
		return
	}

	if num <= 1 {
		return
	}

	if parent, ok := ap.findParentNode(lit); ok {
		if genDecl, ok := parent.(*ast.GenDecl); ok && genDecl.Tok == token.CONST {
			return
		}
	}

	ap.numberObf.AddNumber(num)
}

func (ap *ASTProcessor) findParentNode(node ast.Node) (ast.Node, bool) {
	var parent ast.Node
	var found bool
	
	ast.Inspect(ap.currentFile, func(n ast.Node) bool {
		if n == nil {
			return false
		}
		ast.Inspect(n, func(child ast.Node) bool {
			if child == node {
				parent = n
				found = true
				return false
			}
			return true
		})
		return !found
	})
	
	return parent, found
}

func (ap *ASTProcessor) ProcessTypeSpec(typeSpec *ast.TypeSpec) {
	if !ap.config.ObfuscateTypes {
		return
	}
	
	if typeSpec.Name == nil {
		return
	}
	
	if shouldSkipType(typeSpec.Name.Name) {
		return
	}
	
	typeInfo := ap.typeObf.AddType(typeSpec.Name.Name)
	if typeInfo == nil {
		return
	}
	
	if structType, ok := typeSpec.Type.(*ast.StructType); ok {
		for _, field := range structType.Fields.List {
			ap.collectTypeReferences(typeSpec.Name.Name, field.Type)
			
			if ap.config.ObfuscateFields {
				for _, name := range field.Names {
					ap.fieldObf.AddField(name.Name)
				}
			}
		}
	}
}

func (ap *ASTProcessor) collectTypeReferences(typeName string, expr ast.Expr) {
	switch t := expr.(type) {
	case *ast.Ident:
		ap.typeObf.AddTypeReference(typeName, t.Name)
	case *ast.StarExpr:
		ap.collectTypeReferences(typeName, t.X)
	case *ast.ArrayType:
		ap.collectTypeReferences(typeName, t.Elt)
	case *ast.MapType:
		ap.collectTypeReferences(typeName, t.Key)
		ap.collectTypeReferences(typeName, t.Value)
	case *ast.StructType:
		for _, field := range t.Fields.List {
			ap.collectTypeReferences(typeName, field.Type)
		}
	}
}

func (ap *ASTProcessor) ProcessField(field *ast.Field) {
	if !ap.config.ObfuscateStructs && !ap.config.ObfuscateFields {
		return
	}
	
	if field.Names == nil || len(field.Names) == 0 {
		return
	}

	var tagStr string
	if field.Tag != nil {
		tagStr = field.Tag.Value
	}
	
	for _, name := range field.Names {
		if name.Name == "" {
			continue
		}
		
		if ast.IsExported(name.Name) && !ap.config.ObfuscateFields {
			continue
		}
		
		info := &FieldInfo{
			Original: name.Name,
			ObfName:  GenerateHash("field", name.Name),
			Tag:      tagStr,
		}
		ap.fieldObf.fields[name.Name] = info
		
		if !ast.IsExported(name.Name) && ap.config.ObfuscateStructs {
			ap.identifierObf.AddIdentifier(name.Name)
		}
	}
}

func (ap *ASTProcessor) ProcessAssignStmt(assign *ast.AssignStmt) {
	if !ap.config.ObfuscateVars {
		return
	}
	
	for _, lhs := range assign.Lhs {
		ident, ok := lhs.(*ast.Ident)
		if !ok {
			continue
		}
		
		if ident.Name == "" || ast.IsExported(ident.Name) {
			continue
		}
		
		ap.identifierObf.AddIdentifier(ident.Name)
	}
}

func (ap *ASTProcessor) ProcessGenDecl(decl *ast.GenDecl) {
	if !ap.config.ObfuscateVars || decl.Tok != token.VAR {
		return
	}
	
	for _, spec := range decl.Specs {
		valueSpec, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		
		for _, name := range valueSpec.Names {
			if name.Name == "" || ast.IsExported(name.Name) {
				continue
			}
			ap.identifierObf.AddIdentifier(name.Name)
		}
	}
}

func (ap *ASTProcessor) ProcessIfStmt(ifStmt *ast.IfStmt) {
	if !ap.config.ObfuscateMBA || ifStmt.Cond == nil {
		return
	}
	
	ifStmt.Cond = ap.mbaObf.ObfuscateCondition(ifStmt.Cond)
}

func (ap *ASTProcessor) ProcessForStmt(forStmt *ast.ForStmt) {
	if !ap.config.ObfuscateMBA || forStmt.Cond == nil {
		return
	}
	
	forStmt.Cond = ap.mbaObf.ObfuscateCondition(forStmt.Cond)
}

func (ap *ASTProcessor) ProcessSwitchStmt(switchStmt *ast.SwitchStmt) {
	if !ap.config.ObfuscateMBA || switchStmt.Tag == nil {
		return
	}
	
	switchStmt.Tag = ap.mbaObf.ObfuscateCondition(switchStmt.Tag)
}

// ===== FILE PROCESSOR =====

type FileProcessor struct {
	astProcessor *ASTProcessor
	fset         *token.FileSet
}

func NewFileProcessor(config *Config) *FileProcessor {
	return &FileProcessor{
		astProcessor: NewASTProcessor(config),
		fset:         token.NewFileSet(),
	}
}

func (fp *FileProcessor) ProcessFile(filename string) error {
	node, err := ReadParseFile(fp.fset, filename)
	if err != nil {
		return err
	}
	
	fp.astProcessor.currentFile = node 
	ast.Inspect(node, fp.astProcessor.ProcessNode)
	return nil
}

func (fp *FileProcessor) RewriteFile(filename string) error {
	node, err := ReadParseFile(fp.fset, filename)
	if err != nil {
		return err
	}
	
	changed := fp.RewriteAST(node)
	if !changed {
		return nil
	}
	
	if err := WriteFormattedFile(filename, node, fp.fset); err != nil {
		return err
	}
	
	fmt.Printf("Obfuscated functions, identifiers, numbers, and types in %s\n", filename)
	return nil
}

func (fp *FileProcessor) RewriteAST(node *ast.File) bool {
	changed := false
	
	ast.Inspect(node, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncDecl:
			if newName, ok := fp.astProcessor.functionObf.GetObfuscatedName(node.Name.Name); ok {
				node.Name = ast.NewIdent(newName)
				changed = true
			}
		case *ast.CallExpr:
			if ident, ok := node.Fun.(*ast.Ident); ok {
				if newName, ok := fp.astProcessor.functionObf.GetObfuscatedName(ident.Name); ok {
					node.Fun = ast.NewIdent(newName)
					changed = true
				}
			}
		case *ast.BasicLit:
			if fp.astProcessor.config.ObfuscateNumbers && node.Kind == token.INT {
				if num, err := strconv.ParseInt(node.Value, 10, 64); err == nil {
					if info, ok := fp.astProcessor.numberObf.numbers[num]; ok {
						node.Value = info.ObfExpr
						changed = true
					}
				}
			}
		case *ast.TypeSpec:
			if fp.astProcessor.config.ObfuscateTypes && node.Name != nil {
				if newName, ok := fp.astProcessor.typeObf.GetObfuscatedName(node.Name.Name); ok {
					node.Name.Name = newName
					changed = true
				}
			}
		case *ast.Ident:
			if fp.astProcessor.config.ObfuscateTypes {
				if newName, ok := fp.astProcessor.typeObf.GetObfuscatedName(node.Name); ok {
					node.Name = newName
					changed = true
				}
			}
			if fp.astProcessor.config.ObfuscateVars {
				if newName, ok := fp.astProcessor.identifierObf.GetObfuscatedName(node.Name); ok {
					node.Name = newName
					changed = true
				}
			}
		case *ast.KeyValueExpr:
			if fp.astProcessor.config.ObfuscateFields {
				if ident, ok := node.Key.(*ast.Ident); ok {
					if newName, ok := fp.astProcessor.fieldObf.GetObfuscatedName(ident.Name); ok {
						node.Key = ast.NewIdent(newName)
						changed = true
					}
				}
			}

		case *ast.Field:
			if fp.astProcessor.config.ObfuscateFields && node.Names != nil {
				for _, name := range node.Names {
					if newName, ok := fp.astProcessor.fieldObf.GetObfuscatedName(name.Name); ok {
						name.Name = newName
						changed = true
					}
				}
			}

		case *ast.SelectorExpr:	
			if fp.astProcessor.config.ObfuscateFields {
				if newName, ok := fp.astProcessor.fieldObf.GetObfuscatedName(node.Sel.Name); ok {
					node.Sel.Name = newName
					changed = true
				}
			}
		case *ast.IfStmt:
			if fp.astProcessor.config.ObfuscateMBA && node.Cond != nil {
				newCond := fp.astProcessor.mbaObf.ObfuscateCondition(node.Cond)
				if newCond != node.Cond {
					node.Cond = newCond
					changed = true
				}
			}
		case *ast.ForStmt:
			if fp.astProcessor.config.ObfuscateMBA && node.Cond != nil {
				newCond := fp.astProcessor.mbaObf.ObfuscateCondition(node.Cond)
				if newCond != node.Cond {
					node.Cond = newCond
					changed = true
				}
			}
		case *ast.SwitchStmt:
			if fp.astProcessor.config.ObfuscateMBA && node.Tag != nil {
				newTag := fp.astProcessor.mbaObf.ObfuscateCondition(node.Tag)
				if newTag != node.Tag {
					node.Tag = newTag
					changed = true
				}
			}
		}
		return true
	})
	
	return changed
}

// ===== CODE GENERATOR =====

type CodeGenerator struct {
	stringObf *StringObfuscator
	numberObf *NumberObfuscator
	outputDir string
}

func NewCodeGenerator(stringObf *StringObfuscator, numberObf *NumberObfuscator, outputDir string) *CodeGenerator {
	return &CodeGenerator{
		stringObf: stringObf,
		numberObf: numberObf,
		outputDir: outputDir,
	}
}

func (cg *CodeGenerator) GeneratePreprocFile() error {
	if err := os.MkdirAll(cg.outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	strings := cg.stringObf.GetAllStrings()
	numbers := cg.numberObf.GetAllNumbers()

	tmpl := `// Code generated by genobf.go. DO NOT EDIT.

package include

var obfMap = map[string]func() string{
{{range .Strings}}	"{{.Ident}}": {{.Ident}},
{{end}}}

{{range .Strings}}
// {{.Ident}} returns the deobfuscated string: {{.Original}}
func {{.Ident}}() string {
	var result []byte
	data := []byte{ {{range $i, $b := .Encrypted}}{{if $i}}, {{end}}0x{{printf "%02X" $b}}{{end}} }
	key := byte(0x{{printf "%02X" .Key}})
	result = make([]byte, len(data))
	for i := range data {
		result[i] = data[i] ^ key
	}
	return string(result)
}
{{end}}

{{range .Numbers}}
func {{.Ident}}() int64 {
	return {{.ObfExpr}}
}
{{end}}
`

	t, err := template.New("preproc").Parse(tmpl)
	if err != nil {
		return fmt.Errorf("failed to parse template: %v", err)
	}

	file, err := os.Create(filepath.Join(cg.outputDir, "preproc.go"))
	if err != nil {
		return fmt.Errorf("failed to create preproc.go: %v", err)
	}
	defer file.Close()

	data := struct {
		Strings []*StringInfo
		Numbers []*NumberInfo
	}{
		Strings: strings,
		Numbers: numbers,
	}

	if err := t.Execute(file, data); err != nil {
		return fmt.Errorf("failed to execute template: %v", err)
	}

	fmt.Printf("Generated %s/preproc.go with %d obfuscated strings and %d obfuscated numbers\n", cg.outputDir, len(strings), len(numbers))
	return nil
}

// ===== MAIN COORDINATOR =====

type OBFGenerator struct {
	config        *Config
	fileProcessor *FileProcessor
	codeGenerator *CodeGenerator
}

func NewOBFGenerator(config *Config) *OBFGenerator {
	fileProcessor := NewFileProcessor(config)
	codeGenerator := NewCodeGenerator(
		fileProcessor.astProcessor.stringObf,
		fileProcessor.astProcessor.numberObf,
		config.OutputDir,
	)
	
	return &OBFGenerator{
		config:        config,
		fileProcessor: fileProcessor,
		codeGenerator: codeGenerator,
	}
}

func (g *OBFGenerator) ProcessFiles() error {
	var goFiles []string
	
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		if info.IsDir() {
			return g.ShouldSkipDirectory(info.Name())
		}
		
		if filepath.Ext(path) != ".go" {
			return nil
		}
		
		goFiles = append(goFiles, path)
		fmt.Printf("Processing %s...\n", path)
		
		if err := g.fileProcessor.ProcessFile(path); err != nil {
			return fmt.Errorf("error processing %s: %v", path, err)
		}
		
		return nil
	})
	
	if err != nil {
		return fmt.Errorf("error walking files: %v", err)
	}
	
	for _, f := range goFiles {
		if err := g.fileProcessor.RewriteFile(f); err != nil {
			return fmt.Errorf("error rewriting %s: %v", f, err)
		}
	}
	
	if err := g.codeGenerator.GeneratePreprocFile(); err != nil {
		return fmt.Errorf("error generating preproc.go: %v", err)
	}
	
	if err := g.RewriteSourceFiles(); err != nil {
		return fmt.Errorf("error rewriting source files: %v", err)
	}
	
	return nil
}

func (g *OBFGenerator) ShouldSkipDirectory(dirName string) error {
	for _, skipDir := range g.config.SkipDirs {
		if dirName == skipDir {
			return filepath.SkipDir
		}
	}
	return nil
}

func (g *OBFGenerator) RewriteSourceFiles() error {
	return filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		if info.IsDir() {
			return g.ShouldSkipDirectory(info.Name())
		}
		
		if filepath.Ext(path) != ".go" || path == filepath.Join(g.config.OutputDir, "preproc.go") {
			return nil
		}
		
		return g.RewriteOBFCalls(path)
	})
}

func (g *OBFGenerator) RewriteOBFCalls(path string) error {
	node, err := ReadParseFile(g.fileProcessor.fset, path)
	if err != nil {
		return err
	}

	changed := false
	rewritten := map[token.Pos]string{}

	ast.Inspect(node, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || !isObfCall(call) {
			return true
		}
		str := extractStringFromArg(call.Args[0])
		if str != "" {
			if info, ok := g.fileProcessor.astProcessor.stringObf.strings[str]; ok {
				call.Fun = &ast.SelectorExpr{
					X:   ast.NewIdent("include"),
					Sel: ast.NewIdent(info.Ident),
				}
				call.Args = []ast.Expr{}
				changed = true
				rewritten[call.Pos()] = str
			}
		}
		return true
	})

	if !changed {
		return nil
	}

	if err := WriteFormattedFile(path, node, g.fileProcessor.fset); err != nil {
		return err
	}

	fmt.Printf("Rewrote %s with obfuscated function calls\n", path)
	return nil
}

// ===== CONFIGURATION =====

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

// ===== MAIN =====

func main() {
	config := NewConfig()
	generator := NewOBFGenerator(config)
	
	if err := generator.ProcessFiles(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	
	fmt.Println("Comprehensive obfuscation generation and source rewriting completed successfully!")
} 
