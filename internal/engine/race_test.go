//go:build race

package engine_test

// raceEnabled scales timing budgets: the race detector slows evaluation by
// close to an order of magnitude, and a budget sized for one build flakes
// on the other.
const raceEnabled = true
