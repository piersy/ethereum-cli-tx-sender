package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/urfave/cli/v2"
)

var (
	client *ethclient.Client
)

func main() {
	app := &cli.App{
		Name:  "ethtx",
		Usage: "Ethereum transaction builder and sender",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "rpc",
				Usage:    "Ethereum RPC URL",
				Required: true,
				EnvVars:  []string{"ETH_RPC_URL"},
			},
		},
		Before: func(c *cli.Context) error {
			var err error
			client, err = ethclient.Dial(c.String("rpc"))
			return err
		},
		Commands: []*cli.Command{
			{
				Name:  "send",
				Usage: "Build, sign and send a transaction",
				Flags: commonTxFlags(true),
				Action: func(c *cli.Context) error {
					return handleTransaction(c, true, true)
				},
			},
			{
				Name:  "build",
				Usage: "Build and output unsigned transaction",
				Flags: commonTxFlags(false),
				Action: func(c *cli.Context) error {
					return handleTransaction(c, false, false)
				},
			},
			{
				Name:  "sign",
				Usage: "Build, sign and output signed transaction",
				Flags: commonTxFlags(true),
				Action: func(c *cli.Context) error {
					return handleTransaction(c, true, false)
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func commonTxFlags(includePrivateKey bool) []cli.Flag {
	flags := []cli.Flag{
		&cli.StringFlag{
			Name:     "from",
			Usage:    "Sender address (for nonce and chain ID)",
			Required: true,
		},
		&cli.StringFlag{
			Name:  "to",
			Usage: "Recipient address (empty for contract creation)",
		},
		&cli.StringFlag{
			Name:  "value",
			Usage: "Value to send (in wei)",
			Value: "0",
		},
		&cli.StringFlag{
			Name:  "data",
			Usage: "Transaction data (hex encoded)",
			Value: "",
		},
		&cli.Uint64Flag{
			Name:  "nonce",
			Usage: "Nonce (omit to fetch from network)",
		},
		&cli.Uint64Flag{
			Name:  "gas",
			Usage: "Gas limit (omit for estimate)",
		},
		&cli.StringFlag{
			Name:  "gas-price",
			Usage: "Gas price (in wei, legacy transactions)",
		},
		&cli.StringFlag{
			Name:  "max-fee",
			Usage: "Max fee per gas (in wei, EIP-1559)",
		},
		&cli.StringFlag{
			Name:  "max-priority-fee",
			Usage: "Max priority fee per gas (in wei, EIP-1559)",
		},
		&cli.Uint64Flag{
			Name:  "chain-id",
			Usage: "Chain ID (omit to fetch from network)",
		},
		&cli.Uint64Flag{
			Name:  "type",
			Usage: "Transaction type (0: legacy, 1: access list, 2: EIP-1559)",
			Value: 2,
		},
	}

	if includePrivateKey {
		flags = append(flags, &cli.StringFlag{
			Name:     "private-key",
			Usage:    "Private key (hex format)",
			Required: true,
			EnvVars:  []string{"ETH_PRIVATE_KEY"},
		})
	}

	return flags
}

func handleTransaction(c *cli.Context, sign bool, send bool) error {
	ctx := context.Background()

	// Parse common parameters
	from := common.HexToAddress(c.String("from"))
	var to *common.Address
	if toStr := c.String("to"); toStr != "" {
		addr := common.HexToAddress(toStr)
		to = &addr
	}

	value, ok := new(big.Int).SetString(c.String("value"), 10)
	if !ok {
		return fmt.Errorf("invalid value")
	}

	var data []byte
	if dataStr := c.String("data"); dataStr != "" {
		var err error
		data, err = hex.DecodeString(strings.TrimPrefix(dataStr, "0x"))
		if err != nil {
			return fmt.Errorf("invalid data: %v", err)
		}
	}

	// Fetch chain ID if not provided
	chainID := new(big.Int).SetUint64(c.Uint64("chain-id"))
	if chainID.Uint64() == 0 {
		var err error
		chainID, err = client.NetworkID(ctx)
		if err != nil {
			return fmt.Errorf("failed to get chain ID: %v", err)
		}
	}

	// Get nonce if not provided
	nonce := c.Uint64("nonce")
	if nonce == 0 {
		var err error
		nonce, err = client.PendingNonceAt(ctx, from)
		if err != nil {
			return fmt.Errorf("failed to get nonce: %v", err)
		}
	}

	// Create transaction based on type
	var tx *types.Transaction
	txType := c.Uint64("type")

	switch txType {
	case 0: // Legacy
		gasPrice, ok := new(big.Int).SetString(c.String("gas-price"), 10)
		if !ok {
			suggestedGasPrice, err := client.SuggestGasPrice(ctx)
			if err != nil {
				return fmt.Errorf("failed to get gas price: %v", err)
			}
			gasPrice = suggestedGasPrice
		}

		gasLimit := c.Uint64("gas")
		if gasLimit == 0 {
			msg := ethereum.CallMsg{
				From:     from,
				To:       to,
				GasPrice: gasPrice,
				Value:    value,
				Data:     data,
			}
			estimatedGas, err := client.EstimateGas(ctx, msg)
			if err != nil {
				return fmt.Errorf("failed to estimate gas: %v", err)
			}
			gasLimit = estimatedGas
		}

		tx = types.NewTransaction(nonce, *to, value, gasLimit, gasPrice, data)

	case 1: // Access List (not fully implemented in this example)
		return fmt.Errorf("access list transactions not yet implemented")

	case 2: // EIP-1559
		maxFee, ok := new(big.Int).SetString(c.String("max-fee"), 10)
		if !ok {
			header, err := client.HeaderByNumber(ctx, nil)
			if err != nil {
				return fmt.Errorf("failed to get header: %v", err)
			}
			maxFee = new(big.Int).Mul(header.BaseFee, big.NewInt(2))
		}

		maxPriorityFee, ok := new(big.Int).SetString(c.String("max-priority-fee"), 10)
		if !ok {
			maxPriorityFee = big.NewInt(1e9) // 1 Gwei default
		}

		gasLimit := c.Uint64("gas")
		if gasLimit == 0 {
			msg := ethereum.CallMsg{
				From:      from,
				To:        to,
				GasFeeCap: maxFee,
				GasTipCap: maxPriorityFee,
				Value:     value,
				Data:      data,
			}
			estimatedGas, err := client.EstimateGas(ctx, msg)
			if err != nil {
				return fmt.Errorf("failed to estimate gas: %v", err)
			}
			gasLimit = estimatedGas
		}

		tx = types.NewTx(&types.DynamicFeeTx{
			ChainID:   chainID,
			Nonce:     nonce,
			GasTipCap: maxPriorityFee,
			GasFeeCap: maxFee,
			Gas:       gasLimit,
			To:        to,
			Value:     value,
			Data:      data,
		})

	default:
		return fmt.Errorf("unsupported transaction type: %d", txType)
	}

	marshalled, err := json.MarshalIndent(tx, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal tx to display representation: %w", err)
	}
	fmt.Printf("Transaction: %v\n", string(marshalled))

	// Sign if requested
	var signedTx *types.Transaction
	if sign {
		privateKeyHex := strings.TrimPrefix(c.String("private-key"), "0x")
		privateKey, err := crypto.HexToECDSA(privateKeyHex)
		if err != nil {
			return fmt.Errorf("invalid private key: %v", err)
		}

		signer := types.LatestSignerForChainID(chainID)
		signedTx, err = types.SignTx(tx, signer, privateKey)
		if err != nil {
			return fmt.Errorf("failed to sign transaction: %v", err)
		}
	}

	// Output or send
	if send {
		if !sign {
			return fmt.Errorf("cannot send unsigned transaction")
		}
		err := client.SendTransaction(ctx, signedTx)
		if err != nil {
			return fmt.Errorf("failed to send transaction: %v", err)
		}
		fmt.Printf("Transaction sent: %s\n", signedTx.Hash().Hex())
	} else {
		var output []byte
		if sign {
			output, err = signedTx.MarshalBinary()
			if err != nil {
				return fmt.Errorf("failed marshal transaction to binary format: %v", err)
			}
		} else {
			output, _ = tx.MarshalBinary()
			if err != nil {
				return fmt.Errorf("failed marshal transaction to binary format: %v", err)
			}
		}
		fmt.Printf("0x%s\n", hex.EncodeToString(output))
	}

	return nil
}
