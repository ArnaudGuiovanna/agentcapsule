package accounting

import (
	"math"
	"testing"
)

func TestTokenCostRoundsTheSumOfBothDirections(t *testing.T) {
	if cost, ok := TokenCost(1, 1, 500000, 500000); !ok || cost != 1 {
		t.Fatal(cost, ok)
	}
	if cost, ok := TokenCost(1000000, 0, math.MaxInt64, 0); !ok || cost != math.MaxInt64 {
		t.Fatal(cost, ok)
	}
	if _, ok := TokenCost(1000001, 0, math.MaxInt64, 0); ok {
		t.Fatal("overflow")
	}
}
