package main

import(
	"fmt"
	"github.com/renproject/shamir/ed25519"
	"github.com/renproject/shamir/ed25519/shamirutil"
)

func main(){
	n := 20
	indices := shamirutil.RandomIndices(n)
	shares := make(ed25519.Shares, n)
	k := shamirutil.RandRange(1, n)
	secret := ed25519.RandomScalar()
	err := ed25519.ShareSecret(&shares, indices, secret, k)
	if nil!=err{
		panic("Secret share failed.")
	}
	recon := ed25519.Open(shares)
	if recon.Eq(&secret){
		fmt.Println("Secret sharing and opening successful")
	}
}