// Package accounting computes model usage charges in integer micro-units.
package accounting

import (
	"math/big"
)

// tokenCost is the estimated cost, in micro-units, of input and output tokens
// at prices in micro-units per million tokens, rounded up once so that an
// estimate never under-reports. It is exact: the products do not fit in 64
// bits at the accepted bounds (10^12 tokens, 10^12 per million), so they are
// computed on big integers. ok is false if the cost does not fit in an int64.
func tokenCost(input, output, inputPrice, outputPrice int64) (int64, bool) {
	sum := new(big.Int).Mul(big.NewInt(input), big.NewInt(inputPrice))
	sum.Add(sum, new(big.Int).Mul(big.NewInt(output), big.NewInt(outputPrice)))
	sum.Add(sum, big.NewInt(999_999))
	sum.Quo(sum, big.NewInt(1_000_000))
	if !sum.IsInt64() {
		return 0, false
	}
	return sum.Int64(), true
}

// unitCost is ceil(a*b/d), exact.
func unitCost(a, b, d int64) (int64, bool) {
	v := new(big.Int).Mul(big.NewInt(a), big.NewInt(b))
	v.Add(v, big.NewInt(d-1))
	v.Quo(v, big.NewInt(d))
	if !v.IsInt64() {
		return 0, false
	}
	return v.Int64(), true
}
