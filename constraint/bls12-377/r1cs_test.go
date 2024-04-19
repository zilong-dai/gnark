// Copyright 2020 ConsenSys Software Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by gnark DO NOT EDIT

package cs_test

import (
	"bytes"
	"github.com/zilong-dai/gnark/frontend"
	"github.com/zilong-dai/gnark/frontend/cs/r1cs"
	"github.com/zilong-dai/gnark/frontend/cs/scs"
	"github.com/zilong-dai/gnark/internal/backend/circuits"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	cs "github.com/zilong-dai/gnark/constraint/bls12-377"

	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
)

func TestSerialization(t *testing.T) {

	var buffer, buffer2 bytes.Buffer

	for name := range circuits.Circuits {
		t.Run(name, func(t *testing.T) {
			tc := circuits.Circuits[name]

			r1cs1, err := frontend.Compile(fr.Modulus(), r1cs.NewBuilder, tc.Circuit)
			if err != nil {
				t.Fatal(err)
			}
			if testing.Short() && r1cs1.GetNbConstraints() > 50 {
				return
			}

			// compile a second time to ensure determinism
			r1cs2, err := frontend.Compile(fr.Modulus(), r1cs.NewBuilder, tc.Circuit)
			if err != nil {
				t.Fatal(err)
			}

			{
				buffer.Reset()
				t.Log(name)
				var err error
				var written, read int64
				written, err = r1cs1.WriteTo(&buffer)
				if err != nil {
					t.Fatal(err)
				}
				var reconstructed cs.R1CS
				read, err = reconstructed.ReadFrom(&buffer)
				if err != nil {
					t.Fatal(err)
				}
				if written != read {
					t.Fatal("didn't read same number of bytes we wrote")
				}

				// compare original and reconstructed
				if diff := cmp.Diff(r1cs1, &reconstructed,
					cmpopts.IgnoreFields(cs.R1CS{},
						"System.q",
						"field",
						"CoeffTable.mCoeffs",
						"System.lbWireLevel",
						"System.genericHint",
						"System.SymbolTable",
						"System.bitLen")); diff != "" {
					t.Fatalf("round trip mismatch (-want +got):\n%s", diff)
				}
			}

			// ensure determinism in compilation / serialization / reconstruction
			{
				buffer.Reset()
				n, err := r1cs1.WriteTo(&buffer)
				if err != nil {
					t.Fatal(err)
				}
				if n == 0 {
					t.Fatal("No bytes are written")
				}

				buffer2.Reset()
				_, err = r1cs2.WriteTo(&buffer2)
				if err != nil {
					t.Fatal(err)
				}

				if !bytes.Equal(buffer.Bytes(), buffer2.Bytes()) {
					t.Fatal("compilation of R1CS is not deterministic")
				}

				var r, r2 cs.R1CS
				n, err = r.ReadFrom(&buffer)
				if err != nil {
					t.Fatal(nil)
				}
				if n == 0 {
					t.Fatal("No bytes are read")
				}
				_, err = r2.ReadFrom(&buffer2)
				if err != nil {
					t.Fatal(nil)
				}

				if !reflect.DeepEqual(r, r2) {
					t.Fatal("compilation of R1CS is not deterministic (reconstruction)")
				}
			}
		})

	}
}

const n = 10000

type circuit struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (circuit *circuit) Define(api frontend.API) error {
	for i := 0; i < n; i++ {
		circuit.X = api.Add(api.Mul(circuit.X, circuit.X), circuit.X, 42)
	}
	api.AssertIsEqual(circuit.X, circuit.Y)
	return nil
}

func BenchmarkSolve(b *testing.B) {

	var w circuit
	w.X = 1
	w.Y = 1
	witness, err := frontend.NewWitness(&w, fr.Modulus())
	if err != nil {
		b.Fatal(err)
	}

	b.Run("scs", func(b *testing.B) {
		var c circuit
		ccs, err := frontend.Compile(fr.Modulus(), scs.NewBuilder, &c)
		if err != nil {
			b.Fatal(err)
		}
		b.Log("scs nbConstraints", ccs.GetNbConstraints())

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = ccs.IsSolved(witness)
		}
	})

	b.Run("r1cs", func(b *testing.B) {
		var c circuit
		ccs, err := frontend.Compile(fr.Modulus(), r1cs.NewBuilder, &c, frontend.WithCompressThreshold(10))
		if err != nil {
			b.Fatal(err)
		}
		b.Log("r1cs nbConstraints", ccs.GetNbConstraints())

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = ccs.IsSolved(witness)
		}
	})

}
