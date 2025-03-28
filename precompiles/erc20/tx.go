package erc20

import (
	"math/big"

	errorsmod "cosmossdk.io/errors"
	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/x/authz"
	bankkeeper "github.com/cosmos/cosmos-sdk/x/bank/keeper"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	cmn "github.com/cosmos/evm/precompiles/common"
	"github.com/cosmos/evm/x/vm/core/vm"
	evmtypes "github.com/cosmos/evm/x/vm/types"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

const (
	// TransferMethod defines the ABI method name for the ERC-20 transfer
	// transaction.
	TransferMethod = "transfer"
	// TransferFromMethod defines the ABI method name for the ERC-20 transferFrom
	// transaction.
	TransferFromMethod = "transferFrom"
)

// SendMsgURL defines the authorization type for MsgSend
var SendMsgURL = sdk.MsgTypeURL(&banktypes.MsgSend{})

// Transfer executes a direct transfer from the caller address to the
// destination address.
func (p *Precompile) Transfer(
	ctx sdk.Context,
	contract *vm.Contract,
	stateDB vm.StateDB,
	method *abi.Method,
	args []interface{},
) ([]byte, error) {
	from := contract.CallerAddress
	to, amount, err := ParseTransferArgs(args)
	if err != nil {
		return nil, err
	}

	return p.transfer(ctx, contract, stateDB, method, from, to, amount)
}

// TransferFrom executes a transfer on behalf of the specified from address in
// the call data to the destination address.
func (p *Precompile) TransferFrom(
	ctx sdk.Context,
	contract *vm.Contract,
	stateDB vm.StateDB,
	method *abi.Method,
	args []interface{},
) ([]byte, error) {
	from, to, amount, err := ParseTransferFromArgs(args)
	if err != nil {
		return nil, err
	}

	return p.transfer(ctx, contract, stateDB, method, from, to, amount)
}

// transfer is a common function that handles transfers for the ERC-20 Transfer
// and TransferFrom methods. It executes a bank Send message if the spender is
// the sender of the transfer, otherwise it executes an authorization.
func (p *Precompile) transfer(
	ctx sdk.Context,
	contract *vm.Contract,
	stateDB vm.StateDB,
	method *abi.Method,
	from, to common.Address,
	amount *big.Int,
) (data []byte, err error) {
	// 전송할 금액과 토큰의 명칭을 사용하여 sdk.Coins 객체를 생성
	coins := sdk.Coins{{Denom: p.tokenPair.Denom, Amount: math.NewIntFromBigInt(amount)}}

	// 9.9 Bank 모듈의 MsgSend 메시지를 생성하여, from 주소에서 to 주소로 코인을 전송
	msg := banktypes.NewMsgSend(from.Bytes(), to.Bytes(), coins)

	if err = msg.Amount.Validate(); err != nil {
		return nil, err
	}

	isTransferFrom := method.Name == TransferFromMethod
	owner := sdk.AccAddress(from.Bytes())
	spenderAddr := contract.CallerAddress
	spender := sdk.AccAddress(spenderAddr.Bytes()) // aka. grantee
	ownerIsSpender := spender.Equals(owner)

	var prevAllowance *big.Int
	if ownerIsSpender {
		// 9.10 ownerIsSpender가 참이면, MsgSend를 직접 실행하여 전송
		msgSrv := bankkeeper.NewMsgServerImpl(p.BankKeeper)
		_, err = msgSrv.Send(ctx, msg)
	} else {
		// 9.11 그렇지 않으면, AuthzKeeper를 사용하여 권한을 확인하고 전송을 실행
		_, _, prevAllowance, err = GetAuthzExpirationAndAllowance(p.AuthzKeeper, ctx, spenderAddr, from, p.tokenPair.Denom)
		if err != nil {
			return nil, ConvertErrToERC20Error(errorsmod.Wrap(err, authz.ErrNoAuthorizationFound.Error()))
		}

		_, err = p.AuthzKeeper.DispatchActions(ctx, spender, []sdk.Msg{msg})
	}

	if err != nil {
		err = ConvertErrToERC20Error(err)
		// This should return an error to avoid the contract from being executed and an event being emitted
		return nil, err
	}

	evmDenom := evmtypes.GetEVMCoinDenom()
	if p.tokenPair.Denom == evmDenom {
		convertedAmount := evmtypes.ConvertAmountTo18DecimalsBigInt(amount)
		p.SetBalanceChangeEntries(cmn.NewBalanceChangeEntry(from, convertedAmount, cmn.Sub),
			cmn.NewBalanceChangeEntry(to, convertedAmount, cmn.Add))
	}

	// 9.12 전송이 성공하면, 전송 이벤트를 발생시킴. 이는 EVM에서 이벤트 로그로 기록됨.
	if err = p.EmitTransferEvent(ctx, stateDB, from, to, amount); err != nil {
		return nil, err
	}

	// 9.13 만약 transferFrom 메서드가 아니라면, true 값을 바이트 배열로 반환
	if !isTransferFrom {
		return method.Outputs.Pack(true)
	}

	// 9.14 transferFrom 메서드의 경우, 새로운 approve amount 계산하고 승인 이벤트를 발생
	var newAllowance *big.Int
	if ownerIsSpender {
		// NOTE: in case the spender is the owner we emit an approval event with
		// the maxUint256 value.
		newAllowance = abi.MaxUint256
	} else {
		newAllowance = new(big.Int).Sub(prevAllowance, amount)
	}

	if err = p.EmitApprovalEvent(ctx, stateDB, from, spenderAddr, newAllowance); err != nil {
		return nil, err
	}

	return method.Outputs.Pack(true)
}
