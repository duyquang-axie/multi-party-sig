package keygen

import (
	"crypto/rand"
	"errors"

	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/internal/types"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/polynomial"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/paillier"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pedersen"
	zksch "github.com/taurusgroup/multi-party-sig/pkg/zk/sch"
)

var _ round.Round = (*round1Prime)(nil)

type round1Prime struct {
	*round1

	secretKey *paillier.SecretKey
}

// Finalize implements round.Round
//
// - sample Paillier (pᵢ, qᵢ)
// - sample Pedersen Nᵢ, sᵢ, tᵢ
// - sample aᵢ  <- 𝔽
// - set Aᵢ = aᵢ⋅G
// - compute Fᵢ(X) = fᵢ(X)⋅G
// - sample ridᵢ <- {0,1}ᵏ
// - sample cᵢ <- {0,1}ᵏ
// - commit to message.
func (r *round1Prime) Finalize(out chan<- *round.Message) (round.Session, error) {
	// generate Paillier and Pedersen
	PaillierSecret := r.secretKey
	SelfPaillierPublic := PaillierSecret.PublicKey
	SelfPedersenPublic, PedersenSecret := PaillierSecret.GeneratePedersen()

	ElGamalSecret, ElGamalPublic := sample.ScalarPointPair(rand.Reader, r.Group())

	// save our own share already so we are consistent with what we receive from others
	SelfShare := r.VSSSecret.Evaluate(r.SelfID().Scalar(r.Group()))

	// set Fᵢ(X) = fᵢ(X)•G
	SelfVSSPolynomial := polynomial.NewPolynomialExponent(r.VSSSecret)

	// generate Schnorr randomness
	SchnorrRand := zksch.NewRandomness(rand.Reader, r.Group(), nil)

	// Sample RIDᵢ
	SelfRID, err := types.NewRID(rand.Reader)
	if err != nil {
		return r, errors.New("failed to sample Rho")
	}
	chainKey, err := types.NewRID(rand.Reader)
	if err != nil {
		return r, errors.New("failed to sample c")
	}

	// commit to data in message 2
	SelfCommitment, Decommitment, err := r.HashForID(r.SelfID()).Commit(
		SelfRID, chainKey, SelfVSSPolynomial, SchnorrRand.Commitment(), ElGamalPublic,
		SelfPedersenPublic.N(), SelfPedersenPublic.S(), SelfPedersenPublic.T())
	if err != nil {
		return r, errors.New("failed to commit")
	}

	// should be broadcast but we don't need that here
	msg := &broadcast2{Commitment: SelfCommitment}
	err = r.BroadcastMessage(out, msg)
	if err != nil {
		return r, err
	}

	nextRound := &round2{
		round1:         r.round1,
		VSSPolynomials: map[party.ID]*polynomial.Exponent{r.SelfID(): SelfVSSPolynomial},
		Commitments:    map[party.ID]hash.Commitment{r.SelfID(): SelfCommitment},
		RIDs:           map[party.ID]types.RID{r.SelfID(): SelfRID},
		ChainKeys:      map[party.ID]types.RID{r.SelfID(): chainKey},
		ShareReceived:  map[party.ID]curve.Scalar{r.SelfID(): SelfShare},
		ElGamalPublic:  map[party.ID]curve.Point{r.SelfID(): ElGamalPublic},
		PaillierPublic: map[party.ID]*paillier.PublicKey{r.SelfID(): SelfPaillierPublic},
		Pedersen:       map[party.ID]*pedersen.Parameters{r.SelfID(): SelfPedersenPublic},
		ElGamalSecret:  ElGamalSecret,
		PaillierSecret: PaillierSecret,
		PedersenSecret: PedersenSecret,
		SchnorrRand:    SchnorrRand,
		Decommitment:   Decommitment,
	}
	return nextRound, nil
}
