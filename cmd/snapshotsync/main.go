package main

import (
	"context"
	"flag"
	"fmt"

	proto_downloader "github.com/ledgerwatch/erigon-lib/gointerfaces/downloader"
	"github.com/ledgerwatch/erigon/turbo/snapshotsync"
	"github.com/ledgerwatch/erigon/turbo/snapshotsync/snapcfg"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	flagChain string
)

func init() {
	flag.StringVar(&flagChain, "chain", "mainnet", "chain")

	flag.Parse()
}

func main() {
	if err := _main(context.Background()); err != nil {
		fmt.Printf("startup error: %s", err)
	}
}

func _main(ctx context.Context) error {
	grpc, err := grpc.Dial("127.0.0.1:9093", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	pd := proto_downloader.NewDownloaderClient(grpc)
	syncer := &SnapshotSyncer{
		downloader: pd,
		chain:      flagChain,
	}

	err = syncer.Download(ctx)
	if err != nil {
		return err
	}
	return nil
}

type SnapshotSyncer struct {
	downloader proto_downloader.DownloaderClient
	chain      string
}

func (s *SnapshotSyncer) Download(ctx context.Context) error {
	preverifiedBlockSnapshots := snapcfg.KnownCfg(s.chain, nil, nil).Preverified
	downloadRequest := make([]snapshotsync.DownloadRequest, 0, 32)
	for _, p := range preverifiedBlockSnapshots {
		downloadRequest = append(downloadRequest, snapshotsync.NewDownloadRequest(nil, p.Name, p.Hash))
	}

	err := snapshotsync.RequestSnapshotsDownload(ctx, downloadRequest, s.downloader)
	if err != nil {
		return err
	}

	return nil
}
