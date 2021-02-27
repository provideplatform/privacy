package merkletree

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"math"
	"math/big"
	"strings"
	"sync"
)

const (
	outOfBounds = "Incorrect index - Index out of bounds"
)

// Node is implementation of types.Node and representation of a single node or leaf in the merkle tree
type Node struct {
	hash   []byte
	index  int
	Parent *Node
}

// BigInt returns the big int representation of the hex'd hash of this node
func (node Node) BigInt() *big.Int {
	i := new(big.Int)
	i.SetString(node.Hash(), 16)
	return i
}

// Hash returns the string representation of the hash of the node
func (node *Node) Hash() string {
	return hex.EncodeToString(node.hash)
}

// Index returns the index of this node in its level
func (node *Node) Index() int {
	return node.index
}

// String returns the hash of this node. Alias to Hash()
func (node Node) String() string {
	return node.Hash()
}

// MemoryMerkleTree is the most basic implementation of a MerkleTree
type MemoryMerkleTree struct {
	Hash     func(data ...[]byte) []byte
	Mutex    sync.RWMutex
	Nodes    [][]*Node
	RootNode *Node
	Digest   hash.Hash
}

func (tree *MemoryMerkleTree) init() {
	if tree.Hash == nil {
		tree.Hash = func(data ...[]byte) []byte {
			digest := tree.Digest
			digest.Reset()
			for i := range data {
				_, err := digest.Write(data[i])
				if err != nil {
					return nil
				}
			}

			return digest.Sum(nil)
		}
	}

	tree.Nodes = make([][]*Node, 1)
}

func (tree *MemoryMerkleTree) resizeVertically() {
	leafs := len(tree.Nodes[0])
	levels := len(tree.Nodes)
	neededLevels := int(math.Ceil(math.Log2(float64(leafs)))) + 1

	if levels < neededLevels {
		n := make([][]*Node, neededLevels)
		copy(n, tree.Nodes)
		tree.Nodes = n
	}
}

func (tree *MemoryMerkleTree) createParent(left, right *Node) *Node {
	parentNode := &Node{
		hash:   tree.Hash(left.hash[:], right.hash[:]),
		Parent: nil,
		index:  right.index / 2, // Parent index is always the current node index divided by two
	}

	left.Parent = parentNode
	right.Parent = parentNode

	return parentNode
}

func (tree *MemoryMerkleTree) propagateChange() (root *Node) {
	tree.resizeVertically()
	levels := len(tree.Nodes)

	lastNodeSibling := func(nodes []*Node, length int) *Node {
		if length%2 == 0 {
			// The added node completed a pair - take the other half
			return nodes[length-2]
		}

		// The added node created new pair - duplicate itself
		return nodes[length-1]
	}

	updateParentLevel := func(parent *Node, parentLevel []*Node) []*Node {
		nextLevelLen := len(parentLevel)
		if parent.index == nextLevelLen { // If the leafs are now odd, The parent needs to expand the level
			parentLevel = append(parentLevel, parent)
		} else {
			parentLevel[parent.index] = parent // If the leafs are now even, The parent is just replaced
		}

		return parentLevel
	}

	for i := 0; i < (levels - 1); i++ {
		var left, right *Node
		levelLen := len(tree.Nodes[i])

		right = tree.Nodes[i][levelLen-1]               // Last inserted node
		left = lastNodeSibling(tree.Nodes[i], levelLen) // Either the other half or himself

		parentNode := tree.createParent(left, right)                     // Create parent hashing the two
		tree.Nodes[i+1] = updateParentLevel(parentNode, tree.Nodes[i+1]) // Update the parent level
	}

	root = tree.Nodes[levels-1][0]
	return root
}

func (tree *MemoryMerkleTree) getNodeSibling(level int, index int) *Node {
	nodesCount := len(tree.Nodes[level])
	if index%2 == 1 {
		return tree.Nodes[level][index-1]
	}

	if index == nodesCount-1 {
		return tree.Nodes[level][index]
	}

	return tree.Nodes[level][index+1]
}

func (tree *MemoryMerkleTree) getLeafSibling(index int) *Node {
	return tree.getNodeSibling(0, index)
}

func (tree *MemoryMerkleTree) getIntermediaryHashesByIndex(index int) (intermediaryHashes []*Node) {
	levels := len(tree.Nodes)
	if levels < 2 {
		return make([]*Node, 0)
	}

	intermediaryHashes = make([]*Node, 1, levels-1)
	intermediaryHashes[0] = tree.getLeafSibling(index)
	index /= 2

	node := tree.Nodes[0][index].Parent
	level := 1
	for node.Parent != nil {
		intermediaryHashes = append(intermediaryHashes, tree.getNodeSibling(level, index))
		level++
		index /= 2
		node = node.Parent
	}

	return intermediaryHashes
}

// Add hashes and inserts data on the next available slot in the tree.
// Also recalculates and recalibrates the tree.
// Returns the index it was inserted and the hash of the new data
func (tree *MemoryMerkleTree) Add(data []byte) (index int, hash string) {
	h := tree.Hash(data)
	val := hex.EncodeToString(h)
	index = tree.Insert(val)
	return index, val
}

// RawAdd adds data to the tree without recalculating the tree
// Returns the index of the leaf and the node
func (tree *MemoryMerkleTree) RawAdd(data []byte) (index int, hash string) {
	h := tree.Hash(data)
	val := hex.EncodeToString(h)
	index, _ = tree.RawInsert(val)
	return index, val
}

// RawInsert creates node out of the hash and pushes it into the tree without recalculating the tree
// Returns the index of the leaf and the node
func (tree *MemoryMerkleTree) RawInsert(hash string) (index int, insertedLeaf MerkleTreeNode) {
	tree.Mutex.RLock()
	index = len(tree.Nodes[0])

	dec, _ := hex.DecodeString(hash)

	leaf := &Node{
		dec,
		index,
		nil,
	}

	tree.Nodes[0] = append(tree.Nodes[0], leaf)
	tree.Mutex.RUnlock()

	return index, leaf
}

// Recalculate recreates the whole tree bottom up and returns the hex string of the new root.
// Great to be used with RawInsert when loading up the tree data.
func (tree *MemoryMerkleTree) Recalculate() (treeRoot string) {
	if tree.Length() == 0 {
		return ""
	}

	tree.resizeVertically()
	levels := len(tree.Nodes)

	for i := 0; i < levels-1; i++ {
		levelLen := len(tree.Nodes[i])
		tree.Nodes[i+1] = make([]*Node, (levelLen/2)+(levelLen%2))
		for j := 0; j < len(tree.Nodes[i]); j += 2 {
			left := tree.Nodes[i][j]
			right := tree.getNodeSibling(i, j)
			tree.Nodes[i+1][j/2] = tree.createParent(left, right)
		}
	}

	tree.RootNode = tree.Nodes[levels-1][0]
	return tree.RootNode.Hash()
}

// Insert creates node out of the hash and pushes it into the tree
// Also recalculates and recalibrates the tree
// Returns the index it was inserted at
func (tree *MemoryMerkleTree) Insert(hash string) (index int) {
	tree.Mutex.RLock()
	index, leaf := tree.RawInsert(hash)

	if index == 0 {
		rootNode, _ := leaf.(*Node)
		tree.RootNode = rootNode
	} else {
		tree.RootNode = tree.propagateChange()
	}

	tree.Mutex.RUnlock()
	return index
}

// IntermediaryHashesByIndex returns all hashes needed to produce the root from the given index
func (tree *MemoryMerkleTree) IntermediaryHashesByIndex(index int) (intermediaryHashes []string, err error) {
	if index >= len(tree.Nodes[0]) {
		return nil, errors.New(outOfBounds)
	}

	hashes := tree.getIntermediaryHashesByIndex(index)
	intermediaryHashes = make([]string, len(hashes))

	for i, h := range hashes {
		intermediaryHashes[i] = h.Hash()
	}

	return intermediaryHashes, nil
}

// ValidateExistence emulates how third party would validate the data. Given original data, the index it is supposed to be and the intermediaryHashes,
// the method validates that this is the correct data for that slot. In production you can just check the HashAt and hash the original data yourself
func (tree *MemoryMerkleTree) ValidateExistence(original []byte, index int, intermediaryHashes []string) (result bool, err error) {
	if index >= len(tree.Nodes[0]) {
		return false, errors.New(outOfBounds)
	}

	var i *big.Int

	treeLeaf := tree.Nodes[0][index]
	leafHash := tree.Hash(original)

	i = new(big.Int)
	i.SetString(string(leafHash), 16)

	if i.Cmp(treeLeaf.BigInt()) != 0 {
		return false, nil
	}

	tempBHash := leafHash

	for _, h := range intermediaryHashes {
		oppositeHash, _ := hex.DecodeString(h)

		if index%2 == 0 {
			tempBHash = tree.Hash(tempBHash[:], oppositeHash[:])
		} else {
			tempBHash = tree.Hash(oppositeHash[:], tempBHash[:])
		}

		index /= 2
	}

	i = new(big.Int)
	i.SetString(string(tempBHash), 16)

	return i.Cmp(tree.RootNode.BigInt()) == 0, nil

}

// Root returns the hash of the root of the tree
func (tree *MemoryMerkleTree) Root() (*string, error) {
	if tree.RootNode == nil {
		return nil, fmt.Errorf("nil root node")
	}
	root := tree.RootNode.Hash()
	return &root, nil
}

// Length returns the count of the tree leafs
func (tree *MemoryMerkleTree) Length() int {
	return len(tree.Nodes[0])
}

// String returns human readable version of the tree
func (tree *MemoryMerkleTree) String() string {
	b := strings.Builder{}

	l := len(tree.Nodes)

	for i := l - 1; i >= 0; i-- {
		ll := len(tree.Nodes[i])
		b.WriteString(fmt.Sprintf("Level: %v, Count: %v\n", i, ll))
		for k := 0; k < ll; k++ {
			b.WriteString(fmt.Sprintf("%v\t", tree.Nodes[i][k].Hash()))
		}
		b.WriteString("\n")
	}

	return b.String()
}

// HashAt returns the hash at given index
func (tree *MemoryMerkleTree) HashAt(index int) (string, error) {
	if index >= len(tree.Nodes[0]) {
		return "", errors.New(outOfBounds)
	}
	return tree.Nodes[0][index].Hash(), nil
}

// MarshalJSON Creates JSON version of the needed fields of the tree
func (tree *MemoryMerkleTree) MarshalJSON() ([]byte, error) {
	root, err := tree.Root()
	if err != nil {
		return nil, err
	}
	res := fmt.Sprintf("{\"root\":\"%v\", \"length\":%v}", *root, tree.Length())
	return []byte(res), nil
}

var defaultDigest = sha256.New()

// NewMerkleTree returns a pointer to an initialized MemoryMerkleTree.
// If hash type not provided, sha256 will be used by default
func NewMerkleTree(h hash.Hash) *MemoryMerkleTree {
	var tree MemoryMerkleTree
	if h == nil {
		tree.Digest = defaultDigest
	} else {
		tree.Digest = h
	}
	tree.init()
	return &tree
}
