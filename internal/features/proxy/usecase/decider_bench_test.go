package usecase_test

import (
	"fmt"
	"testing"

	policydomain "github.com/kabirnarang39/wardline/internal/features/policy/domain"
	policyusecase "github.com/kabirnarang39/wardline/internal/features/policy/usecase"
	"github.com/kabirnarang39/wardline/internal/features/proxy/domain"
	"github.com/kabirnarang39/wardline/internal/features/proxy/usecase"
)

// BenchmarkDecider_Decide measures the in-process policy-decision overhead
// on the request hot path with the default YAML backend — the per-call
// cost Wardline adds before proxying upstream. Run:
//
//	go test -bench=Decide -benchmem ./internal/features/proxy/usecase
func BenchmarkDecider_Decide(b *testing.B) {
	for _, n := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("rules=%d", n), func(b *testing.B) {
			rules := make([]policydomain.Rule, 0, n)
			for i := 0; i < n; i++ {
				rules = append(rules, policydomain.Rule{
					Identity: fmt.Sprintf("agent-%04d", i),
					Tool:     "read_file",
					Effect:   policydomain.EffectAllow,
				})
			}
			engine := policyusecase.NewMatcher(rules, policydomain.EffectDeny)
			d := usecase.NewDecider(engine)
			// Worst realistic case: the matching rule is the last one, so the
			// linear scan runs the full rule set.
			call := domain.ToolCall{Identity: fmt.Sprintf("agent-%04d", n-1), Tool: "read_file"}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if v := d.Decide(call); !v.Allow {
					b.Fatal("expected allow")
				}
			}
		})
	}
}
