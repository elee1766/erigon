package rpcdaemon

import (
	"os"

	"github.com/ledgerwatch/erigon/cmd/devnettest/utils"
	"github.com/ledgerwatch/erigon/cmd/rpcdaemon/cli/httpcfg"

	"github.com/ledgerwatch/erigon-lib/common"
	"github.com/ledgerwatch/erigon/cmd/rpcdaemon/cli"
	"github.com/ledgerwatch/erigon/cmd/rpcdaemon/commands"
	"github.com/ledgerwatch/log/v3"
	"github.com/spf13/cobra"
)

func RunDaemon(flags *utils.RPCFlags) {
	cmd, cfg := cli.RootCommand()
	setUpFlags(cfg, flags)
	rootCtx, rootCancel := common.RootContext()
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		logger := log.New()
		db, borDb, backend, txPool, mining, starknet, stateCache, blockReader, ff, err := cli.RemoteServices(ctx, *cfg, logger, rootCancel)
		if err != nil {
			log.Error("Could not connect to DB", "err", err)
			return nil
		}
		defer db.Close()
		if borDb != nil {
			defer borDb.Close()
		}

		apiList := commands.APIList(db, borDb, backend, txPool, mining, starknet, ff, stateCache, blockReader, *cfg)
		if err := cli.StartRpcServer(ctx, *cfg, apiList); err != nil {
			log.Error(err.Error())
			return nil
		}

		return nil
	}

	if err := cmd.ExecuteContext(rootCtx); err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}
}

func setUpFlags(cfg *httpcfg.HttpCfg, flags *utils.RPCFlags) {
	cfg.WebsocketEnabled = flags.WebsocketEnabled
}