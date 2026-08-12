// Command hacheck verifies the HA scenario's core claim after the load
// finishes: with two replicas sharing one Postgres pool, the combined
// admitted count across BOTH replicas equals the ceiling exactly (not
// double-counted, not raced), and the shared audit trail's row count
// for the scenario's identity equals the total requests sent (nothing
// dropped, nothing duplicated).
//
// Usage:
//
//	hacheck reset <postgres-dsn> <identity>
//	hacheck check <postgres-dsn> <identity> <expected-total-requests> <expected-allowed>
package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strconv"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "reset":
		runReset(os.Args[2:])
	case "check":
		runCheck(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: hacheck reset <postgres-dsn> <identity>")
	fmt.Fprintln(os.Stderr, "       hacheck check <postgres-dsn> <identity> <expected-total-requests> <expected-allowed>")
	os.Exit(2)
}

// runReset deletes any audit_entries rows for identity left over from a
// prior run of this same bench scenario -- audit_entries is a shared
// table across every bench scenario that uses postgres_storage, so this
// scenario's own identity (ha-bench-agent, distinct from every other
// scenario's) is the only thing ever deleted here.
func runReset(args []string) {
	if len(args) != 2 {
		usage()
	}
	dsn, identity := args[0], args[1]
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open db:", err)
		os.Exit(1)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.ExecContext(context.Background(), `DELETE FROM audit_entries WHERE identity = $1`, identity); err != nil {
		fmt.Fprintln(os.Stderr, "reset:", err)
		os.Exit(1)
	}
}

func runCheck(args []string) {
	if len(args) != 4 {
		usage()
	}
	dsn, identity := args[0], args[1]
	expectedTotal, err := strconv.Atoi(args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad expected-total-requests:", err)
		os.Exit(2)
	}
	expectedAllowed, err := strconv.Atoi(args[3])
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad expected-allowed:", err)
		os.Exit(2)
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open db:", err)
		os.Exit(1)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()

	var total, allowed, throttled int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_entries WHERE identity = $1`, identity).Scan(&total); err != nil {
		fmt.Fprintln(os.Stderr, "query total:", err)
		os.Exit(1)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_entries WHERE identity = $1 AND decision = 'allow'`, identity).Scan(&allowed); err != nil {
		fmt.Fprintln(os.Stderr, "query allowed:", err)
		os.Exit(1)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_entries WHERE identity = $1 AND decision = 'throttled'`, identity).Scan(&throttled); err != nil {
		fmt.Fprintln(os.Stderr, "query throttled:", err)
		os.Exit(1)
	}

	fmt.Printf("audit_entries for %q: total=%d allow=%d throttled=%d (expected total=%d, allow=%d)\n",
		identity, total, allowed, throttled, expectedTotal, expectedAllowed)

	ok := true
	if total != expectedTotal {
		fmt.Printf("MISMATCH: total audit rows %d != expected %d -- entries dropped or duplicated across replicas sharing the pool\n", total, expectedTotal)
		ok = false
	}
	if allowed != expectedAllowed {
		fmt.Printf("MISMATCH: allowed count %d != expected ceiling %d -- budget double-counted or raced across replicas\n", allowed, expectedAllowed)
		ok = false
	}
	if !ok {
		os.Exit(1)
	}
	fmt.Println("HA CHECK PASSED: no double-counting, no dropped/duplicated audit entries across replicas")
}
