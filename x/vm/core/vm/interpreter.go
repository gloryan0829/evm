// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package vm

import (
	"hash"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/log"
)

// Config are the configuration options for the Interpreter
type Config struct {
	Debug                   bool      // Enables debugging
	Tracer                  EVMLogger // Opcode logger
	NoBaseFee               bool      // Forces the EIP-1559 baseFee to 0 (needed for 0 price calls)
	EnablePreimageRecording bool      // Enables recording of SHA3/keccak preimages

	JumpTable *JumpTable // EVM instruction table, automatically populated if unset

	ExtraEips []string // Additional EIPS that are to be enabled
}

// ScopeContext contains the things that are per-call, such as stack and memory,
// but not transients like pc and gas
type ScopeContext struct {
	Memory   *Memory
	Stack    *Stack
	Contract *Contract
}

// keccakState wraps sha3.state. In addition to the usual hash methods, it also supports
// Read to get a variable amount of data from the hash state. Read is faster than Sum
// because it doesn't copy the internal state, but also modifies the internal state.
type keccakState interface {
	hash.Hash
	Read([]byte) (int, error)
}

var _ Interpreter = &EVMInterpreter{}

// EVMInterpreter represents an EVM interpreter
type EVMInterpreter struct {
	evm *EVM
	cfg Config

	hasher    keccakState // Keccak256 hasher instance shared across opcodes
	hasherBuf common.Hash // Keccak256 hasher result array shared aross opcodes

	readOnly   bool   // Whether to throw on stateful modifications
	returnData []byte // Last CALL's return data for subsequent reuse
}

// NewEVMInterpreter returns a new instance of the Interpreter.
func NewEVMInterpreter(evm *EVM, cfg Config) *EVMInterpreter {
	// If jump table was not initialised we set the default one.
	if cfg.JumpTable == nil {
		cfg.JumpTable = DefaultJumpTable(evm.chainRules)
		for i, eip := range cfg.ExtraEips {
			// TODO: I think this only relates to Evmos and can be skipped on Cosmos EVM repo
			if len(cfg.ExtraEips) == 1 && eip == "\x8f\x1e" {
				// The protobuf params changed so need to update the EIP for archive calls
				eip = "ethereum_3855"
			}

			// Deep-copy jumptable to prevent modification of opcodes in other tables
			copy := CopyJumpTable(cfg.JumpTable)
			if err := EnableEIP(eip, copy); err != nil {
				// Disable it, so caller can check if it's activated or not
				cfg.ExtraEips = append(cfg.ExtraEips[:i], cfg.ExtraEips[i+1:]...)
				log.Error("EIP activation failed", "eip", eip, "error", err)
			}
			cfg.JumpTable = copy
		}
	}

	return &EVMInterpreter{
		evm: evm,
		cfg: cfg,
	}
}

// EVM returns the EVM instance
func (in *EVMInterpreter) EVM() *EVM {
	return in.evm
}

// Config returns the configuration of the interpreter
func (in EVMInterpreter) Config() Config {
	return in.cfg
}

// ReadOnly returns whether the interpreter is in read-only mode
func (in EVMInterpreter) ReadOnly() bool {
	return in.readOnly
}

// ReturnData gets the last CALL's return data for subsequent reuse
func (in *EVMInterpreter) ReturnData() []byte {
	return in.returnData
}

// SetReturnData sets the last CALL's return data
func (in *EVMInterpreter) SetReturnData(data []byte) {
	in.returnData = data
}

// Run loops and evaluates the contract's code with the given input data and returns
// the return byte-slice and an error if one occurred.
//
// It's important to note that any errors returned by the interpreter should be
// considered a revert-and-consume-all-gas operation except for
// ErrExecutionReverted which means revert-and-keep-gas-left.
// 6.1 컨트랙트 코드를 실행하는 함수
// arg0 - contract: 실행할 바이트코드와 상태 포함
// arg1 - input: 트랜잭션 또는 함수 호출에 전달된 파라미터
// arg2 - readOnly: 상태를 변경하지 않는 호출 여부 (e.g. eth_call) 
func (in *EVMInterpreter) Run(contract *Contract, input []byte, readOnly bool) (ret []byte, err error) {
	// Increment the call depth which is restricted to 1024
	// 6.2 컨트랙트 호출 시 최대 깊이를 1024 로 제한함
	in.evm.depth++
	defer func() { in.evm.depth-- }()

	// Make sure the readOnly is only set if we aren't in readOnly yet.
	// This also makes sure that the readOnly flag isn't removed for child calls.
	// 6.2 상위 컨텍스트가 readOnly인 경우 자식도 readOnly로 고정됨 ( eth_call )
	if readOnly && !in.readOnly {
		in.readOnly = true
		defer func() { in.readOnly = false }()
	}

	// Reset the previous call's return data. It's unimportant to preserve the old buffer
	// as every returning call will return new data anyway.
	// 6.3 이전 트랜잭션의 결과값 초기화
	in.returnData = nil

	// Don't bother with the execution if there's no code.
	// 6.4 코드가 없으면 실행하지 않음
	if len(contract.Code) == 0 {
		return nil, nil
	}

	// 6.5 Memory: EVM이 메모리, Stack: 스택 초기화
	mem := NewMemory()       // bound memory
	stack, err := NewStack() // local stack
	if err != nil {
		return nil, err
	}
	// 6.6 메모리와 스택을 포함한 현재 스코프의 상태 저장
	callContext := &ScopeContext{
		Memory:   mem,
		Stack:    stack,
		Contract: contract,
	}

	var (
		op OpCode // current opcode
		// For optimisation reason we're using uint64 as the program counter.
		// It's theoretically possible to go above 2^64. The YP defines the PC
		// to be uint256. Practically much less so feasible.
		pc   uint64 // program counter
		cost uint64
		// copies used by tracer
		pcCopy  uint64 // needed for the deferred EVMLogger
		gasCopy uint64 // for EVMLogger to log gas remaining before execution
		logged  bool   // deferred EVMLogger should ignore already logged steps
		res     []byte // result of the opcode execution function
	)
	// Don't move this deferred function, it's placed before the capturestate-deferred method,
	// so that it get's executed _after_: the capturestate needs the stacks before
	// they are returned to the pools
	defer ReturnNormalStack(stack)
	contract.Input = input

	if in.cfg.Debug {
		defer func() {
			if err != nil {
				if !logged {
					in.cfg.Tracer.CaptureState(pcCopy, op, gasCopy, cost, callContext, in.returnData, in.evm.depth, err)
				} else {
					in.cfg.Tracer.CaptureFault(pcCopy, op, gasCopy, cost, callContext, in.evm.depth, err)
				}
			}
		}()
	}
	// The Interpreter main run loop (contextual). This loop runs until either an
	// explicit STOP, RETURN or SELFDESTRUCT is executed, an error occurred during
	// the execution of one of the operations or until the done flag is set by the
	// parent context.
	// 6.7 실질적인 EVM 실행 루프를 다루는 코드이며, 
	// STOP, RETURN, SELFDESTRUCT 또는 오류가 발생할 때까지 실행됨
	for {
		if in.cfg.Debug {
			// Capture pre-execution values for tracing.
			logged, pcCopy, gasCopy = false, pc, contract.Gas
		}
		// Get the operation from the jump table and validate the stack to ensure there are
		// enough stack items available to perform the operation.
		op = contract.GetOp(pc) // 6.8 opcode 가져오기
		operation := in.cfg.JumpTable[op] // 6.9 opcode 실행 함수 가져오기
		cost = operation.constantGas // For tracing // 6.10 해당 opcode 실행 비용 가져오기
		// Validate stack
		// 6.11 해당 opcode 실행을 위해 스택 길이가 충분한지 확인
		if sLen := stack.Len(); sLen < operation.minStack {
			return nil, &ErrStackUnderflow{stackLen: sLen, required: operation.minStack}
		} else if sLen > operation.maxStack {
			return nil, &ErrStackOverflow{stackLen: sLen, limit: operation.maxStack}
		}
		// 6.12 해당 opcode 실행 비용 차감 및 체크 => 만약 가스가 부족하면 ErrOutOfGas 반환
		if !contract.UseGas(cost) {
			return nil, ErrOutOfGas
		}
		// 6.13 일부 opcode는 입력값에 따라 가스 비용이 동적으로 계산됨 예: CALL, EXP, MSTORE, LOGx 등
		if operation.dynamicGas != nil {
			// All ops with a dynamic memory usage also has a dynamic gas cost.
			var memorySize uint64
			// calculate the new memory size and expand the memory to fit
			// the operation
			// Memory check needs to be done prior to evaluating the dynamic gas portion,
			// to detect calculation overflows
			if operation.memorySize != nil {
				memSize, overflow := operation.memorySize(stack)
				if overflow {
					return nil, ErrGasUintOverflow
				}
				// memory is expanded in words of 32 bytes. Gas
				// is also calculated in words.
				if memorySize, overflow = math.SafeMul(toWordSize(memSize), 32); overflow {
					return nil, ErrGasUintOverflow
				}
			}
			// Consume the gas and return an error if not enough gas is available.
			// cost is explicitly set so that the capture state defer method can get the proper cost
			// 6.14 동적 가스 비용 계산
			var dynamicCost uint64
			dynamicCost, err = operation.dynamicGas(in.evm, contract, stack, mem, memorySize)
			// 6.15 동적 가스 비용 차감 및 체크 만약 가스가 부족하면 ErrOutOfGas 반환
			cost += dynamicCost // for tracing
			if err != nil || !contract.UseGas(dynamicCost) {
				return nil, ErrOutOfGas
			}
			// Do tracing before memory expansion
			if in.cfg.Debug {
				in.cfg.Tracer.CaptureState(pc, op, gasCopy, cost, callContext, in.returnData, in.evm.depth, err)
				logged = true
			}
			if memorySize > 0 {
				mem.Resize(memorySize)
			}
		} else if in.cfg.Debug {
			in.cfg.Tracer.CaptureState(pc, op, gasCopy, cost, callContext, in.returnData, in.evm.depth, err)
			logged = true
		}
		// 6.16 가장 핵심! → OpCode 별 동작 수행 ( 예: ADD, SLOAD, CALL, RETURN, REVERT 등
		// execute the operation
		res, err = operation.execute(&pc, in, callContext)
		if err != nil {
			break
		}
		pc++
	}

	// 6.17 [6.16] operation.execute 에서 STOP, RETURN, SELFDESTRUCT 등 호출되면 정상 처리
	if err == errStopToken {
		err = nil // clear stop token error
	}

	return res, err
}
