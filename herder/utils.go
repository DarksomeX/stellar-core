package herder

import (
	"github.com/darksomex/stellar-core/scp"
	"github.com/stellar/go/xdr"
)

func getTxSetHashes(env *xdr.ScpEnvelope) []*xdr.Hash {
	values := getStellarValues(&env.Statement)
	result := make([]*xdr.Hash, 0, len(values))

	for _, v := range values {
		result = append(result, &v.TxSetHash)
	}

	return result
}

func getStellarValues(st *xdr.ScpStatement) []*xdr.StellarValue {
	values := scp.GetStatementValues(st)
	result := make([]*xdr.StellarValue, 0, len(values))
	for _, value := range values {
		sv := new(xdr.StellarValue)
		err := sv.UnmarshalBinary(*value)
		if err != nil {
			panic("failed to unmarshal stellar value")
		}
		result = append(result, sv)
	}

	return result
}
