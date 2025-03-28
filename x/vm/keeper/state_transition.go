package keeper

import (
	"math/big"

	cmttypes "github.com/cometbft/cometbft/types"

	errorsmod "cosmossdk.io/errors"
	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"

	cosmosevmtypes "github.com/cosmos/evm/types"
	"github.com/cosmos/evm/x/vm/statedb"
	"github.com/cosmos/evm/x/vm/types"

	evmcore "github.com/cosmos/evm/x/vm/core/core"
	"github.com/cosmos/evm/x/vm/core/vm"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
)

// NewEVM generates a go-ethereum VM from the provided Message fields and the chain parameters
// (ChainConfig and module Params). It additionally sets the validator operator address as the
// coinbase address to make it available for the COINBASE opcode, even though there is no
// beneficiary of the coinbase transaction (since we're not mining).
//
// NOTE: the RANDOM opcode is currently not supported since it requires
// RANDAO implementation. See https://github.com/evmos/ethermint/pull/1520#pullrequestreview-1200504697
// for more information.
func (k *Keeper) NewEVM(
	ctx sdk.Context,
	msg core.Message,
	cfg *statedb.EVMConfig,
	tracer vm.EVMLogger,
	stateDB vm.StateDB,
) *vm.EVM {
	// 3.3 블록 컨텍스트 생성
	blockCtx := vm.BlockContext{
		CanTransfer: evmcore.CanTransfer, // 토큰 전송 가능 여부 함수
		Transfer:    evmcore.Transfer, // 토큰 전송 함수
		GetHash:     k.GetHashFn(ctx), // 블록 해시 함수
		Coinbase:    cfg.CoinBase, // 코인베이스 주소 - 마이닝 매커니증 X -> Cosmos Validator (Proposer) Hex 로 된 주소를 넣어줌. Coinbase opcode 에서 사용됨
		GasLimit:    cosmosevmtypes.BlockGasLimit(ctx), // 블록 가스 한도 (컨센서스 파라미터 설정된 값으로 사용됨 config 에서 가져옴)
		BlockNumber: big.NewInt(ctx.BlockHeight()),
		Time:        big.NewInt(ctx.BlockHeader().Time.Unix()),
		Difficulty:  big.NewInt(0), // 사용 안함 - PoW 아님
		BaseFee:     cfg.BaseFee, // 기본 수수료 0.1 gwei
		Random:      nil, // 사용안함 - 구현되어있지 않음

	}
	// 3.4 트랜잭션 컨텍스트 생성
	txCtx := evmcore.NewEVMTxContext(msg)
	if tracer == nil {
		tracer = k.Tracer(ctx, msg, cfg.ChainConfig)
	}
	// EVM Interpreter의 세부 설정 구조체
	// JumpTable (opcode 테이블)
	vmConfig := k.VMConfig(ctx, msg, cfg, tracer)

	// 3.5 smart contract 생성(CREATE) 혹은 호출(CALL) 권한이 있는지 검사 - e.g 특정 주소만 Smart Contract 생성 가능하거나 호출 가능하도록 제한
	signer := msg.From()
	accessControl := types.NewRestrictedPermissionPolicy(&cfg.Params.AccessControl, signer)

	// EVM opcode(CREATE, CALL) 실행 전후에 사용자 정의 로직 실행 가능
	evmHooks := types.NewDefaultOpCodesHooks()
	evmHooks.AddCreateHooks(
		accessControl.GetCreateHook(signer),
	)
	evmHooks.AddCallHooks(
		accessControl.GetCallHook(signer),
		k.GetPrecompilesCallHook(ctx),
	)
	// 3.6 EVM 인스턴스 생성
	return vm.NewEVMWithHooks(evmHooks, blockCtx, txCtx, stateDB, cfg.ChainConfig, vmConfig)
}

// GetHashFn implements vm.GetHashFunc for Ethermint. It handles 3 cases:
//  1. The requested height matches the current height from context (and thus same epoch number)
//  2. The requested height is from an previous height from the same chain epoch
//  3. The requested height is from a height greater than the latest one
func (k Keeper) GetHashFn(ctx sdk.Context) vm.GetHashFunc {
	return func(height uint64) common.Hash {
		h, err := cosmosevmtypes.SafeInt64(height)
		if err != nil {
			k.Logger(ctx).Error("failed to cast height to int64", "error", err)
			return common.Hash{}
		}

		switch {
		case ctx.BlockHeight() == h:
			// Case 1: The requested height matches the one from the context so we can retrieve the header
			// hash directly from the context.
			// Note: The headerHash is only set at begin block, it will be nil in case of a query context
			headerHash := ctx.HeaderHash()
			if len(headerHash) != 0 {
				return common.BytesToHash(headerHash)
			}

			// only recompute the hash if not set (eg: checkTxState)
			contextBlockHeader := ctx.BlockHeader()
			header, err := cmttypes.HeaderFromProto(&contextBlockHeader)
			if err != nil {
				k.Logger(ctx).Error("failed to cast tendermint header from proto", "error", err)
				return common.Hash{}
			}

			headerHash = header.Hash()
			return common.BytesToHash(headerHash)

		case ctx.BlockHeight() > h:
			// Case 2: if the chain is not the current height we need to retrieve the hash from the store for the
			// current chain epoch. This only applies if the current height is greater than the requested height.
			histInfo, err := k.stakingKeeper.GetHistoricalInfo(ctx, h)
			if err != nil {
				k.Logger(ctx).Debug("error while getting historical info", "height", h, "error", err.Error())
				return common.Hash{}
			}

			header, err := cmttypes.HeaderFromProto(&histInfo.Header)
			if err != nil {
				k.Logger(ctx).Error("failed to cast tendermint header from proto", "error", err)
				return common.Hash{}
			}

			return common.BytesToHash(header.Hash())
		default:
			// Case 3: heights greater than the current one returns an empty hash.
			return common.Hash{}
		}
	}
}

// ApplyTransaction runs and attempts to perform a state transition with the given transaction (i.e Message), that will
// only be persisted (committed) to the underlying KVStore if the transaction does not fail.
//
// # Gas tracking
//
// Ethereum consumes gas according to the EVM opcodes instead of general reads and writes to store. Because of this, the
// state transition needs to ignore the SDK gas consumption mechanism defined by the GasKVStore and instead consume the
// amount of gas used by the VM execution. The amount of gas used is tracked by the EVM and returned in the execution
// result.
//
// Prior to the execution, the starting tx gas meter is saved and replaced with an infinite gas meter in a new context
// in order to ignore the SDK gas consumption config values (read, write, has, delete).
// After the execution, the gas used from the message execution will be added to the starting gas consumed, taking into
// consideration the amount of gas returned. Finally, the context is updated with the EVM gas consumed value prior to
// returning.
//
// For relevant discussion see: https://github.com/cosmos/cosmos-sdk/discussions/9072
func (k *Keeper) ApplyTransaction(ctx sdk.Context, tx *ethtypes.Transaction) (*types.MsgEthereumTxResponse, error) {
	var bloom *big.Int

	cfg, err := k.EVMConfig(ctx, sdk.ConsAddress(ctx.BlockHeader().ProposerAddress))
	if err != nil {
		return nil, errorsmod.Wrap(err, "failed to load evm config")
	}
	txConfig := k.TxConfig(ctx, tx.Hash())

	// get the signer according to the chain rules from the config and block height
	// 2.1 signer : EIP-155 Replay Attack 을 방지하기 위한 ChainID 추가와 그에 따른 서명 방식을 가져옴
	signer := ethtypes.MakeSigner(cfg.ChainConfig, big.NewInt(ctx.BlockHeight()))
	// 2.2 msg : 이더리움 코어 transaction type 에서 트랜잭션을 메시지로 변환
	// 2.3 baseFee : 기본 수수료 0.1 gwei 를 feeMarketKeeper params 에서 가져옴
	// 2.4 내부적으로 baseFee 와 사용자가 지정한 Tip 을 더해서 gasPrice 를 계산함 EIP1559 Gas 산정 방식
	msg, err := tx.AsMessage(signer, cfg.BaseFee)
	if err != nil {
		return nil, errorsmod.Wrap(err, "failed to return ethereum transaction as core message")
	}

	// Create a cache context to revert state. The cache context is only committed when both tx and hooks executed successfully.
	// Didn't use `Snapshot` because the context stack has exponential complexity on certain operations,
	// thus restricted to be used only inside `ApplyMessage`.
	// 2.5 StateDB 는 컨텍스트 기반 캐시 MultiStore 를 생성하여 상태를 롤백할 수 있게 함. 
	// EVM 에서 State 관리를 위한 임시 저장소 개념
	tmpCtx, commit := ctx.CacheContext()

	// pass true to commit the StateDB
	// 2.6 ApplyMessageWithConfig 함수를 호출하여 메시지를 실행하고 변경된 상태를 임시 StateDB 에 커밋 함.
	res, err := k.ApplyMessageWithConfig(tmpCtx, msg, nil, true, cfg, txConfig)
	if err != nil {
		// when a transaction contains multiple msg, as long as one of the msg fails
		// all gas will be deducted. so is not msg.Gas()
		k.ResetGasMeterAndConsumeGas(tmpCtx, tmpCtx.GasMeter().Limit())
		return nil, errorsmod.Wrap(err, "failed to apply ethereum core message")
	}

	logs := types.LogsToEthereum(res.Logs)

	// Compute block bloom filter
	if len(logs) > 0 {
		bloom = k.GetBlockBloomTransient(ctx)
		bloom.Or(bloom, big.NewInt(0).SetBytes(ethtypes.LogsBloom(logs)))
	}

	if !res.Failed() {
		commit()
	}

	evmDenom := types.GetEVMCoinDenom()

	// refund gas in order to match the Ethereum gas consumption instead of the default SDK one.
	if err = k.RefundGas(ctx, msg, msg.Gas()-res.GasUsed, evmDenom); err != nil {
		return nil, errorsmod.Wrapf(err, "failed to refund gas leftover gas to sender %s", msg.From())
	}

	if len(logs) > 0 {
		// Update transient block bloom filter
		k.SetBlockBloomTransient(ctx, bloom)
		k.SetLogSizeTransient(ctx, uint64(txConfig.LogIndex)+uint64(len(logs)))
	}

	k.SetTxIndexTransient(ctx, uint64(txConfig.TxIndex)+1)

	totalGasUsed, err := k.AddTransientGasUsed(ctx, res.GasUsed)
	if err != nil {
		return nil, errorsmod.Wrap(err, "failed to add transient gas used")
	}

	// reset the gas meter for current cosmos transaction
	k.ResetGasMeterAndConsumeGas(ctx, totalGasUsed)
	return res, nil
}

// ApplyMessage calls ApplyMessageWithConfig with an empty TxConfig.
func (k *Keeper) ApplyMessage(ctx sdk.Context, msg core.Message, tracer vm.EVMLogger, commit bool) (*types.MsgEthereumTxResponse, error) {
	cfg, err := k.EVMConfig(ctx, sdk.ConsAddress(ctx.BlockHeader().ProposerAddress))
	if err != nil {
		return nil, errorsmod.Wrap(err, "failed to load evm config")
	}

	txConfig := statedb.NewEmptyTxConfig(common.BytesToHash(ctx.HeaderHash()))
	return k.ApplyMessageWithConfig(ctx, msg, tracer, commit, cfg, txConfig)
}

// ApplyMessageWithConfig computes the new state by applying the given message against the existing state.
// If the message fails, the VM execution error with the reason will be returned to the client
// and the transaction won't be committed to the store.
//
// # Reverted state
//
// The snapshot and rollback are supported by the `statedb.StateDB`.
//
// # Different Callers
//
// It's called in three scenarios:
// 1. `ApplyTransaction`, in the transaction processing flow.
// 2. `EthCall/EthEstimateGas` grpc query handler.
// 3. Called by other native modules directly.
//
// # Prechecks and Preprocessing
//
// All relevant state transition prechecks for the MsgEthereumTx are performed on the AnteHandler,
// prior to running the transaction against the state. The prechecks run are the following:
//
// 1. the nonce of the message caller is correct
// 2. caller has enough balance to cover transaction fee(gaslimit * gasprice)
// 3. the amount of gas required is available in the block
// 4. the purchased gas is enough to cover intrinsic usage
// 5. there is no overflow when calculating intrinsic gas
// 6. caller has enough balance to cover asset transfer for **topmost** call
//
// The preprocessing steps performed by the AnteHandler are:
//
// 1. set up the initial access list (iff fork > Berlin)
//
// # Tracer parameter
//
// It should be a `vm.Tracer` object or nil, if pass `nil`, it'll create a default one based on keeper options.
//
// # Commit parameter
//
// If commit is true, the `StateDB` will be committed, otherwise discarded.
func (k *Keeper) ApplyMessageWithConfig(
	ctx sdk.Context,
	msg core.Message,
	tracer vm.EVMLogger,
	commit bool,
	cfg *statedb.EVMConfig,
	txConfig statedb.TxConfig,
) (*types.MsgEthereumTxResponse, error) {
	var (
		ret   []byte // return bytes from evm execution
		vmErr error  // vm errors do not effect consensus and are therefore not assigned to err
	)

	// 3.1 StateDB 는 컨텍스트 기반으로 상태 관리를 위한 임시 저장소
	stateDB := statedb.New(ctx, k, txConfig)
	// 3.2 EVM 인스턴스를 생성하여 이더리움 코어 메시지를 실행할 수 있게 함
	evm := k.NewEVM(ctx, msg, cfg, tracer, stateDB)

	// 4.1 msg 에서 가스 한도 가져와 leftoverGas 변수에 초기화 함
	leftoverGas := msg.Gas()

	// Allow the tracer captures the tx level events, mainly the gas consumption.
	vmCfg := evm.Config
	if vmCfg.Debug {
		vmCfg.Tracer.CaptureTxStart(leftoverGas)
		defer func() {
			vmCfg.Tracer.CaptureTxEnd(leftoverGas)
		}()
	}

	sender := vm.AccountRef(msg.From())
	contractCreation := msg.To() == nil
	isLondon := cfg.ChainConfig.IsLondon(evm.Context.BlockNumber)

	// 4.2 intrinsicGas 는 트랜잭션 실행에 필요한 최소 가스 양을 계산하는 함수 (트랜잭션 실행 전 계산)
	intrinsicGas, err := k.GetEthIntrinsicGas(ctx, msg, cfg.ChainConfig, contractCreation)
	if err != nil {
		// should have already been checked on Ante Handler
		return nil, errorsmod.Wrap(err, "intrinsic gas failed")
	}
	// Should check again even if it is checked on Ante Handler, because eth_call don't go through Ante Handler.
    // 4.3 만약 Msg GasLimit 이 4.2 에서 계산된 가스보다 작으면 오류 발생
	if leftoverGas < intrinsicGas {
		// eth_estimateGas will check for this exact error
		return nil, errorsmod.Wrap(core.ErrIntrinsicGas, "apply message")
	}
	// 4.4 Msg GasLimit 에서 내부 가스 계산한 값을 빼서 남은 가스를 leftoverGas 에 저장
	leftoverGas -= intrinsicGas

	// access list preparation is moved from ante handler to here, because it's needed when `ApplyMessage` is called
	// under contexts where ante handlers are not run, for example `eth_call` and `eth_estimateGas`.
	// 4.5 만약 Berlin 이후 블록이면 access list 를 준비하는데 EIP2929 에 정의된 대로 트랜잭션 실행되기 전 미리 데이터의 위치를 정의하여 가스 비용을 최적화 함.
	if rules := cfg.ChainConfig.Rules(big.NewInt(ctx.BlockHeight()), cfg.ChainConfig.MergeNetsplitBlock != nil); rules.IsBerlin {
		// The access list is prepared without any precompile because it is
		// filled with only the recipient precompile address in the EVM'hook
		// call.
		stateDB.PrepareAccessList(msg.From(), msg.To(), []common.Address{}, msg.AccessList())
	}

	// 4.6 만약 메시지가 컨트랙트를 생성하는 CREATE 메시지라면, 해당 Sender 의 Address 의 Nonce 를 조회하고, 
	//EVM CREATE 를 한 이후 다시 Nonce 를 증가시켜 임시 StateDB 에 저장함
	if contractCreation {
		// take over the nonce management from evm:
		// - reset sender's nonce to msg.Nonce() before calling evm.
		// - increase sender's nonce by one no matter the result.
		// 4.7 Nonce 를 임시 StateDB 에 저장하고 evm.Create 이후 다시 Nonce 를 1 증가시킵니다. 아마도, 다음 트랜잭션의 경우
		// 이더리움 컨트랙트 주소체계가 Sender 주소와 nonce 로 이루어지기 때문에 중복되지 않게 하기 위해 이와 같은 방식을 사용하는 것 같음
		stateDB.SetNonce(sender.Address(), msg.Nonce())
		ret, _, leftoverGas, vmErr = evm.Create(sender, msg.Data(), leftoverGas, msg.Value())
		stateDB.SetNonce(sender.Address(), msg.Nonce()+1)
	} else {
		ret, leftoverGas, vmErr = evm.Call(sender, *msg.To(), msg.Data(), leftoverGas, msg.Value())
	}

	// 10.1 London 포크 이전 (50% 환불)
	refundQuotient := params.RefundQuotient

	// After EIP-3529: refunds are capped to gasUsed / 5
	// 10.2 가스 환불 계산 -> 환불 가스 = (현재 가스 - 남은 가스, 사용가스) / 환불 비율 (20% 환불)
	if isLondon {
		refundQuotient = params.RefundQuotientEIP3529
	}

	// calculate gas refund
	if msg.Gas() < leftoverGas {
		return nil, errorsmod.Wrap(types.ErrGasOverflow, "apply message")
	}
	// refund gas
	temporaryGasUsed := msg.Gas() - leftoverGas
	refund := GasToRefund(stateDB.GetRefund(), temporaryGasUsed, refundQuotient)

	// update leftoverGas and temporaryGasUsed with refund amount
	// 10.3 실행이후 남은 가스에 환불 가스를 더하고, 사용한 가스에서는 환불 가스를 빼줌
	leftoverGas += refund
	temporaryGasUsed -= refund

	// EVM execution error needs to be available for the JSON-RPC client
	var vmError string
	if vmErr != nil {
		vmError = vmErr.Error()
	}

	// The dirty states in `StateDB` is either committed or discarded after return
	// 10.4 커밋 여부 확인 후 StateDB 에 커밋 처리
	if commit {
		if err := stateDB.Commit(); err != nil {
			return nil, errorsmod.Wrap(err, "failed to commit stateDB")
		}
	}

	// calculate a minimum amount of gas to be charged to sender if GasLimit
	// is considerably higher than GasUsed to stay more aligned with Tendermint gas mechanics
	// for more info https://github.com/evmos/ethermint/issues/1085
	gasLimit := math.LegacyNewDec(int64(msg.Gas())) //#nosec G115 -- int overflow is not a concern here -- msg gas is not exceeding int64 max value
	minGasMultiplier := k.GetMinGasMultiplier(ctx)
	minimumGasUsed := gasLimit.Mul(minGasMultiplier)

	if !minimumGasUsed.TruncateInt().IsUint64() {
		return nil, errorsmod.Wrapf(types.ErrGasOverflow, "minimumGasUsed(%s) is not a uint64", minimumGasUsed.TruncateInt().String())
	}

	if msg.Gas() < leftoverGas {
		return nil, errorsmod.Wrapf(types.ErrGasOverflow, "message gas limit < leftover gas (%d < %d)", msg.Gas(), leftoverGas)
	}

	gasUsed := math.LegacyMaxDec(minimumGasUsed, math.LegacyNewDec(int64(temporaryGasUsed))).TruncateInt().Uint64() //#nosec G115 -- int overflow is not a concern here
	// reset leftoverGas, to be used by the tracer
	leftoverGas = msg.Gas() - gasUsed

	// 10.5 최종 결과 반환
	return &types.MsgEthereumTxResponse{
		GasUsed: gasUsed,
		VmError: vmError,
		Ret:     ret,
		Logs:    types.NewLogsFromEth(stateDB.Logs()),
		Hash:    txConfig.TxHash.Hex(),
	}, nil
}
