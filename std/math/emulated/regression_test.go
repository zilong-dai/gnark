package emulated

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/zilong-dai/gnark/frontend"
	"github.com/zilong-dai/gnark/std/math/emulated/emparams"
	"github.com/zilong-dai/gnark/test"
)

type testIssue867Circuit struct {
	A, B Element[emparams.BW6761Fp]
	// Res  Element[emparams.BW6761Fp]
}

func (c *testIssue867Circuit) Define(api frontend.API) error {
	f, err := NewField[emparams.BW6761Fp](api)
	if err != nil {
		return err
	}
	f.Div(&c.A, &c.B)
	return nil
}

func TestIssue867Division(t *testing.T) {
	ac := Element[emparams.BW6761Fp]{
		Limbs:    make([]frontend.Variable, 23),
		overflow: 72,
		internal: true,
	}
	bc := Element[emparams.BW6761Fp]{
		Limbs:    make([]frontend.Variable, 23),
		overflow: 118,
		internal: true,
	}
	a := Element[emparams.BW6761Fp]{
		Limbs: []frontend.Variable{
			"42152055455558239410918856365347934987",
			"284096672345318884331906744025751994436",
			"614038234500395071520584452045854556036",
			"650791570547517983681540124631549305906",
			"1015426967328780486983265586758233548314",
			"1547576981782048968201287533960518281592",
			"2241388874175174864705300518494392715473",
			"2272776063523064079117175149406828917348",
			"2108034997939354830629994253650658395093",
			"2496638612325105562443710658519436256202",
			"2516535160396097216063035076559950097396",
			"2851622448053604742119299279390439519900",
			"1745307545739213351161058618528459959073",
			"1611333894983919176759905895818287768762",
			"1466950300593143231048571873514528370337",
			"1413148907163753703359561383721137311278",
			"1106632639185048629298472160281839189795",
			"223485414995874678448933378505248108260",
			"498894012096407228249522197291620119508",
			"66456820497382616360969181916422224388",
			"418687747092845373939573067221695941200",
			"929739253206827109560966422852970160",
			"516235675893857489524743064330668",
		},
		overflow: 72,
		internal: true,
	}
	b := Element[emparams.BW6761Fp]{
		Limbs: []frontend.Variable{
			"1225996432692727976601767167989361746138121889728902418",
			"1225996432692726898457503589717765703850589432813740752",
			"1225996432692727601202002035504082609034686265426224534",
			"1225996432692727863800627065585502400025688697839624688",
			"1225996432692726895840280725330019244557638565515208816",
			"1225996432692728388244995609757388577021081951481986580",
			"1225996432692726531118348372019113404206525154000451880",
			"1225996432692726447731005019972770765499945195971883848",
			"1225996432692727744357066134208375801833920991141279930",
			"1225996432692726890371778721001659042419189436317645960",
			"1225996432692724521956555855212298329189894636085023472",
			"1225996432692727669349649012761793837315979800575415838",
			"1225996432692728342310921852357706757313945745570174496",
			"1225996432692727633381606696459772297983693097833527678",
			"1225996432692727495940982271275341035852610611137245606",
			"1225996432692728288709439232109402555258221126516325320",
			"1225996432692726848720378195875416806833757401249877456",
			"1225996432692727083894468774663851695073095308036985598",
			"1225996432692728230861854324679838743877597377148752472",
			"1225996432692726866241709451789414581782249958783970800",
			"1225996432692728208615724450642876467256539219504282232",
			"1225996432692728509987163825647123386984338675020339462",
			"1225996432692728509159175754185978068065410668081643970",
		},
		overflow: 118,
		internal: true,
	}
	test.IsSolved(&testIssue867Circuit{A: ac, B: bc}, &testIssue867Circuit{A: a, B: b}, ecc.BLS12_381.ScalarField())
}

type testIssue1021Circuit struct {
	A Element[BN254Fp]
}

func (c *testIssue1021Circuit) Define(api frontend.API) error {
	f, err := NewField[BN254Fp](api)
	if err != nil {
		return err
	}
	b := f.NewElement(c.A)
	p := f.Modulus()
	for i := 0; i < 188; i++ {
		b = f.Add(b, p)
	}
	f.AssertIsEqual(b, &c.A)
	return nil
}

func TestIssue1021(t *testing.T) {
	assert := test.NewAssert(t)
	err := test.IsSolved(&testIssue1021Circuit{}, &testIssue1021Circuit{A: ValueOf[BN254Fp](10)}, ecc.BN254.ScalarField())
	assert.NoError(err)
}
